import uuid
import logging

from config import celery_app

import socket
from imaplib import IMAP4
import mailparser

from cortex4py.api import Api

# from pymisp import PyMISP

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from methlab.shop.models import InternalInfo
from methlab.utils.importer import MethMail

User = get_user_model()


class CeleryError(Exception):
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


@celery_app.task
def check_mails():
    try:
        info = InternalInfo.objects.first()
        inbox = IMAP4(info.imap_server)
        inbox.starttls()
        inbox.login(info.imap_username, info.imap_password)
        inbox.select(info.imap_folder)
    except ObjectDoesNotExist:
        logging.error("missing information")
        raise CeleryError
    except (IMAP4.error, ConnectionRefusedError, socket.gaierror):
        logging.error("error connecting to imap")
        raise CeleryError

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
        raise CeleryError

    # try:
    #    if info.http_proxy and info.https_proxy:
    #        misp_api = PyMISP(
    #            info.misp_url,
    #            info.misp_api,
    #            proxies={"http": info.http_proxy, "https": info.https_proxy},
    #            ssl=False,
    #        )
    #    else:
    #        misp_api = PyMISP(info.misp_url, info.misp_api, ssl=False)
    # except Exception:
    # raise CeleryError
    misp_api = None

    _, data = inbox.search(None, "(UNSEEN)")
    email_list = list(data[0].split())
    data_list = []
    for number in email_list:
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
            logging.error(e)
            continue
        logging.debug("PARSING MAIL {}".format(number))
        methmail = MethMail(
            msg,
            info=info,
            cortex_api=cortex_api,
            misp_api=misp_api,
            mail_filepath=filepath,
        )
        methmail.process_mail()
    return len(data_list)
