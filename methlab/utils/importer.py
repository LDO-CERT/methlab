import os
import sys
import django

# import json

sys.path.append("/app")

os.environ["DATABASE_URL"] = "postgres://{}:{}@{}:{}/{}".format(
    os.environ["POSTGRES_USER"],
    os.environ["POSTGRES_PASSWORD"],
    os.environ["POSTGRES_HOST"],
    os.environ["POSTGRES_PORT"],
    os.environ["POSTGRES_DB"],
)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")
django.setup()

import pytz  # noqa
import uuid  # noqa
import spf  # noqa
import mailparser  # noqa
import dateutil  # noqa
from django.utils import timezone  # noqa
from imaplib import IMAP4  # noqa
from dateutil.parser import parse  # noqa
from tldextract import extract  # noqa
from cortex4py.api import Api  # noqa

from ioc_finder import (  # noqa
    parse_urls,
    parse_ipv4_addresses,
    parse_ipv4_cidrs,
    parse_ipv6_addresses,
    parse_email_addresses,
)
from methlab.shop.models import (  # noqa
    Mail,
    Attachment,
    Address,
    InternalInfo,
    Mail_Flag,
    Flag,
    Ioc,
    Mail_Addresses,
)

# DA RIMUOVERE
Attachment.objects.all().delete()
Address.objects.all().delete()
Mail.objects.all().delete()

info = InternalInfo.objects.first()
inbox = IMAP4(info.imap_server)
inbox.starttls()
inbox.login(info.imap_username, info.imap_password)
inbox.select(info.imap_folder)


# CORTEX API
if info.http_proxy and info.https_proxy:
    cortex_api = Api(
        info.cortex_url,
        info.cortex_api,
        proxies={"http": info.http_proxy, "https": info.https_proxy},
        verify_cert=False,
    )
else:
    cortex_api = Api(info.cortex_url, info.cortex_api, verify_cert=False)


def store_attachments(msg):
    # store attachment to disk
    random_path = "/tmp/{}".format(uuid.uuid4())
    os.makedirs(random_path)
    msg.write_attachments(random_path)
    return random_path


def check_cortex(ioc, ioc_type):
    try:
        job = cortex_api.analyzers.run_by_name(
            "VirusTotal_GetReport_3_0",
            {"data": ioc, "dataType": ioc_type, "tlp": 1},
            force=1,
        )
        while job.status not in ["Success"]:
            job = cortex_api.jobs.get_report(job.id)
            print(job.id, job.status)
        return job.json()
    except Exception as excp:
        print(ioc, ioc_type, excp)


def process_mail(msg, parent_id=None):

    # IF MAIL WAS ALREADY PROCESSED IGNORE
    try:
        mail = Mail.objects.get(message_id=msg.message_id, parent_id__pk=parent_id)
    except Mail.DoesNotExist:
        pass

    flags = []

    # CHECK ADDRESSES AND ASSIGN FLAGS
    addresses_list = []
    for (name, address_from) in msg.from_:
        address, _ = Address.objects.get_or_create(name=name, address=address_from)
        addresses_list.append((address, "from"))
        other_addresses = parse_email_addresses(name)
        if len(other_addresses) > 0 and any([x != mail for x in other_addresses]):
            flags.append((Flag.objects.get(name="Fake Real Name"), None))
        if info.vip_list:
            for vip in info.vip_list:
                if name.find(vip) != -1 and mail.find(info.vip_domain) == -1:
                    flags.append(
                        (
                            Flag.objects.get(name="Potenziale VIP SCAM"),
                            "{} mail for {}".format(name, vip),
                        )
                    )
    for (name, address) in msg.to:
        address, _ = Address.objects.get_or_create(name=name, address=address)
        addresses_list.append((address, "to"))
    for (name, address) in msg.bcc:
        address, _ = Address.objects.get_or_create(name=name, address=address)
        addresses_list.append((address, "bcc"))
    for (name, address) in msg.cc:
        address, _ = Address.objects.get_or_create(name=name, address=address)
        addresses_list.append((address, "cc"))
    for (name, address) in msg.reply_to:
        address, _ = Address.objects.get_or_create(name=name, address=address)
        addresses_list.append((address, "reply_to"))

    # CHECK SPF & INTERNAL FROM FIRST HOP
    first_hop = next(iter(msg.received), None)
    if first_hop:
        ip = parse_ipv4_addresses(first_hop.get("from", []))
        domain = first_hop.get("by", None)
        if len(ip) > 0 and domain:
            ip = ip[0]
            domain = domain.split()[0]
            sender = msg.from_[0][1]
            spf_check = spf.check(s=sender, i=ip, h=domain)
            if spf_check[1] != 250:
                flags.append(
                    (
                        Flag.objects.get(name="SPF"),
                        "Sender {0} non accettato via SPF sul server {1} ({2}): {3}. Hop considerato: {4}".format(
                            sender, domain, ip, spf_check[2], first_hop,
                        ),
                    )
                )
        if (
            domain
            and info.internal_domains
            and any([internal.find(domain) != -1 for internal in info.internal_domains])
        ):
            flags.append((Flag.objects.get(name="Internal"), None))

    if not msg.date:
        date = timezone.now()
    else:
        date = parse("{} {}".format(msg.date, msg.timezone.replace(".", ":")))

    mail = Mail(
        parent=None if parent_id is None else Mail(parent_id),
        message_id=msg.message_id,
        subject=msg.subject,
        date=date,
        received=msg.received,
        headers=msg.headers,
        defects=msg.defects,
        defects_categories=[x for x in msg.defects_categories],
        text_plain=msg.text_plain,
        text_not_managed=msg.text_not_managed,
        body=msg.body,
        body_plain=msg.body_plain,
        sender_ip_address=msg.sender_ip_address,
        to_domains=msg.to_domains,
    )
    mail.save()

    for addr_item, addr_type in addresses_list:
        addr_obj = Mail_Addresses(mail=mail, address=addr_item, field=addr_type)
        addr_obj.save()
        if addr_type == "to":
            if info.security_emails and addr_obj.address.name in info.security_emails:
                mail.tags.add("SecInc")
            if info.honeypot_emails and addr_obj.address.name in info.honeypot_emails:
                mail.tags.add("Honeypot")
        elif addr_type == "cc":
            if info.security_emails and addr_obj.address.name in info.security_emails:
                mail.tags.add("SecInc")
    if mail.tags.count() == 0:
        mail.tags.add("Hunting")

    # Save attachments
    random_path = store_attachments(msg)

    # PROCESS ATTACHMENTS
    for mess_att in msg.attachments:
        whitelisted = False

        # I don't have payload or I don't understand type
        if not mess_att["mail_content_type"] or not mess_att["payload"]:
            continue

        # If is in whitelist I'll skip
        if info.mimetype_whitelist:
            for wl in info.mimetype_whitelist:
                if mess_att["mail_content_type"].startswith(wl):
                    whitelisted = True
                    break
        if whitelisted:
            continue

        _, fileext = os.path.splitext(mess_att["filename"])
        file_path = "{}/{}".format(random_path, mess_att["filename"])

        if (
            mess_att["mail_content_type"] == "application/octet-stream"
            and fileext in (".eml", ".msg")
        ) or mess_att["mail_content_type"] == "message/rfc822":
            internal_message = mailparser.parse_from_file(file_path)
            process_mail(internal_message, mail.pk)

        elif mess_att["mail_content_type"] in ("text/plain", "text/html",):
            for url in parse_urls(mess_att["payload"]):
                url = url.split(">")[0].rstrip('"].').strip("/").lower()
                ioc, _ = Ioc.objects.get_or_create(
                    domain=".".join(part for part in extract(url) if part),
                )

                # import pdb
                # pdb.set_trace()

                if ioc.urls and url not in ioc.urls:
                    ioc.urls.append(url)
                    ioc.save()
                elif not ioc.urls:
                    ioc.urls = [url]
                    ioc.save()
                mail.iocs.add(ioc)
                if not ioc.whitelisted:
                    # result = check_cortex(url, "url")
                    pass

            for ip in (
                parse_ipv4_addresses(mess_att["payload"])
                + parse_ipv4_cidrs(mess_att["payload"])
                + parse_ipv6_addresses(mess_att["payload"])
            ):
                ioc, _ = Ioc.objects.get_or_create(ip=ip)
                mail.iocs.add(ioc)
                if not ioc.whitelisted:
                    # result = check_cortex(ip, "url")
                    pass

        else:
            fix_mail_dict = dict((k.replace("-", "_"), v) for k, v in mess_att.items())
            attachment = Attachment(**fix_mail_dict)
            attachment.mail = mail
            attachment.filepath = file_path
            attachment.save()
            # result = check_cortex(file_path, "file")

    # STORE FLAGS IN DB
    for flag, note in flags:
        mf = Mail_Flag(mail=mail, flag=flag, note=note)
        mf.save()


def main():
    _, data = inbox.search(None, "ALL")
    email_list = list(reversed(data[0].split()))
    for number in email_list:
        _, data = inbox.fetch(number, "(RFC822)")

        # IF PARSE FAILS IGNORE
        try:
            msg = mailparser.parse_from_bytes(data[0][1])
        except Exception as e:
            print("ERROR", e)
            continue
        process_mail(msg)


if __name__ == "__main__":
    main()
