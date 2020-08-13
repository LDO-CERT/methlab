import os
import sys
import django

sys.path.append("/app")

os.environ["DATABASE_URL"] = "postgres://{}:{}@{}:{}/{}".format(
    os.environ["POSTGRES_USER"],
    os.environ["POSTGRES_PASSWORD"],
    os.environ["POSTGRES_HOST"],
    os.environ["POSTGRES_PORT"],
    os.environ["POSTGRES_DB"],
)

os.environ["CELERY_BROKER_URL"] = "redis://redis:6379/0"

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")
django.setup()

import uuid
import socket
from imaplib import IMAP4
import mailparser
from cortex4py.api import Api

# from pymisp import PyMISP

from django.core.exceptions import ObjectDoesNotExist
from methlab.shop.models import InternalInfo
from methlab.utils.importer import MethMail


class Error(Exception):
    pass


def store_mail(content):
    """ Saves mail as file to send it to cortex analyzers.

        arguments:
        - content: mail payload to write on disk

        returns:
        - eml_path: path on disk
    """
    eml_path = "/tmp/{}.eml".format(uuid.uuid4())
    with open(eml_path, "wb") as f:
        f.write(content)
    return eml_path


if __name__ == "__main__":
    try:
        info = InternalInfo.objects.first()
        inbox = IMAP4(info.imap_server)
        inbox.starttls()
        inbox.login(info.imap_username, info.imap_password)
        inbox.select(info.imap_folder)
    except ObjectDoesNotExist:
        raise Error
    except (IMAP4.error, ConnectionRefusedError, socket.gaierror):
        raise Error

    try:
        if info.http_proxy and info.https_proxy:
            cortex_api = Api(
                info.cortex_url,
                info.cortex_api,
                proxies={"http": info.http_proxy, "https": info.https_proxy},
                verify_cert=False,
            )
        else:
            cortex_api = Api(info.cortex_url, info.cortex_api, verify_cert=False)
    except Exception:
        raise Error

    misp_api = None

    _, data = inbox.search(None, "(ALL)")
    email_list = list(data[0].split())
    data_list = []
    for number in email_list[50:160]:
        _, data = inbox.fetch(number, "(RFC822)")
        data_list.append(data[0][1])
    inbox.close()
    inbox.logout()

    for content in data_list:
        # IF PARSE FAILS IGNORE
        try:
            filepath = store_mail(content)
            msg = mailparser.parse_from_bytes(content)
        except Exception as e:
            print(e)
            continue
        methmail = MethMail(
            msg,
            info=info,
            cortex_api=cortex_api,
            misp_api=misp_api,
            mail_filepath=filepath,
        )
        methmail.process_mail()
    print(len(data_list))
