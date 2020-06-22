import ssl
import asyncio
import mailparser
from aioimaplib import aioimaplib

from methlab.shop.models import Mail, Attachment, Address, InternalInfo

from django.core.management.base import BaseCommand


def clean_all_data():
    Attachment.objects.all().delete()
    Address.objects.all().delete()
    Mail.objects.all().delete()


# Monkey patching aioimaplib to support starttls
async def protocol_starttls(self, host, ssl_context=None):
    if "STARTTLS" not in self.capabilities:
        aioimaplib.Abort("server does not have STARTTLS capability")
    if hasattr(self, "_tls_established") and self._tls_established:
        aioimaplib.Abort("TLS session already established")

    response = await self.execute(
        aioimaplib.Command("STARTTLS", self.new_tag(), loop=self.loop)
    )
    if response.result != "OK":
        return response

    if ssl_context is None:
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    sock = self.transport.get_extra_info("socket")
    print("SOCK", sock)
    sock.setblocking(True)
    sock = ssl_context.wrap_socket(sock, server_hostname=host)
    sock.setblocking(False)
    self.transport._sock = sock
    self._tls_established = True

    await self.capability()

    return response


async def imap_starttls(self):
    return await asyncio.wait_for(self.protocol.starttls(self.host), self.timeout)


aioimaplib.IMAP4ClientProtocol.starttls = protocol_starttls
aioimaplib.IMAP4.starttls = imap_starttls


async def process_mail(msg, parent_id=None):
    print(msg)


class Command(BaseCommand):
    help = "Monitor inbox"

    def handle(self, *args, **kwargs):
        clean_all_data()
        self.stdout.write("start")

        info = InternalInfo.objects.first()
        if not info:
            self.stdout.write(self.style.ERROR("Missing information. EXIT!"))
            return

        @asyncio.coroutine
        def _check_inbox():
            imap_client = aioimaplib.IMAP4(info.imap_server)
            yield from imap_client.wait_hello_from_server()
            yield from imap_client.starttls()

            yield from imap_client.login(info.imap_username, info.imap_password)
            response = yield from imap_client.select(info.imap_folder)

            while True:
                response = yield from imap_client.uid("fetch", "1:*", "RFC822")
                iterator = iter(response.lines[:-1])
                for start, middle, _end in zip(iterator, iterator, iterator):
                    if not isinstance(middle, bytes):
                        continue
                    email_uid = start.split(" ")[3]
                    try:
                        msg = mailparser.parse_from_bytes(middle)
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR("Error parsing email {}.".format(e))
                        )
                    process_mail(msg)
                    self.stdout.write(
                        self.style.SUCCESS("Email {} parsed.".format(email_uid))
                    )
                idle = yield from imap_client.idle_start(timeout=60)
                print((yield from imap_client.wait_server_push()))

                imap_client.idle_done()
                yield from asyncio.wait_for(idle, 30)

        asyncio.run(_check_inbox())
        self.stdout.write("end")
