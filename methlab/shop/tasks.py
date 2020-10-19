import uuid
import time
import logging
import datetime

import socket
import mailparser
from imaplib import IMAP4

from config import celery_app
from glom import glom, PathAccessError

from cortex4py.api import Api

from django.core.exceptions import ObjectDoesNotExist

from django.contrib.contenttypes.models import ContentType

from methlab.shop.models import (
    InternalInfo,
    Analyzer,
    Address,
    Mail,
    Attachment,
    Report,
    Ioc,
)
from methlab.utils.importer import MethMail


class CeleryError(Exception):
    pass


def store_mail(content):
    """Saves mail as file to send it to cortex analyzers.

    arguments:
    - content: mail payload to write on disk

    returns:
    - eml_path: path on disk
    """
    eml_path = "/tmp/{}.eml".format(uuid.uuid4())
    with open(eml_path, "wb") as f:
        f.write(content)
    return eml_path


def get_info(mail=True, cortex=True):
    try:
        info = InternalInfo.objects.first()
    except (ObjectDoesNotExist, AttributeError):
        logging.error("missing information")
        raise CeleryError

    # MAIL ITEM ONLY ONCE
    if mail:
        try:
            info = InternalInfo.objects.first()
            inbox = IMAP4(info.imap_server)
            inbox.starttls()
            inbox.login(info.imap_username, info.imap_password)
            inbox.select(info.imap_folder)
        except (ObjectDoesNotExist, AttributeError):
            logging.error("missing information")
            raise CeleryError
        except (IMAP4.error, ConnectionRefusedError, socket.gaierror):
            logging.error("error connecting to imap")
            raise CeleryError
    else:
        inbox = None

    # CORTEX CHECK NOT ON MAIL DOWNLOAD
    if cortex:
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
    else:
        cortex_api = None
    return info, inbox, cortex_api


@celery_app.task(name="check_cortex")
def check_cortex(ioc, ioc_type, object_id, is_mail=False):
    """Run all available analyzer for ioc.

    arguments:
    - ioc: value/path of item we need to check on cortex
    - ioc_type: type of the ioc (generic_relation and cortex datatype)
    - object_id: item to attach report to
    - is_mail: ioc is a mail [mail datatype is for addresses and file is for mail]
    """

    _, _, cortex_api = get_info(mail=False)

    # Mail object is file in cortex
    # need to save mail object analyzer as mail_obj to discriminate them
    filter_type = ioc_type if not is_mail else "mail_obj"
    analyzers = Analyzer.objects.filter(
        disabled=False, supported_types__contains=[filter_type]
    ).order_by("-priority")

    if ioc_type == "mail" and is_mail is False:
        content_type = Address
        analyzers = analyzers.filter(onpremise=True)
    elif ioc_type == "mail" and is_mail is True:
        content_type = Mail
    elif ioc_type in ["url", "ip"]:
        content_type = Ioc
    elif ioc_type == "file":
        content_type = Attachment
        analyzers = analyzers.filter(onpremise=True)

    old_reports = Report.objects.filter(
        content_type=ContentType.objects.get_for_model(content_type),
        object_id=object_id,
        success=True,
        date__gte=datetime.datetime.today() - datetime.timedelta(days=30),
    )

    db_object = content_type.objects.get(pk=object_id)

    for analyzer in analyzers:

        # Check if item was already been processed
        for report in old_reports:
            if report.analyzer == analyzer:
                if "malicious" in report.taxonomies:
                    db_object.tags.add(
                        "{}: malicious".format(analyzer.name),
                        tag_kwargs={"color": "#FF0000"},
                    )

                elif "suspicious" in report.taxonomies:
                    db_object.tags.add(
                        "{}: suspicious".format(analyzer.name),
                        tag_kwargs={"color": "#C15808"},
                    )

                elif "safe" in report.taxonomies:
                    db_object.tags.add(
                        "{}: safe".format(analyzer.name),
                        tag_kwargs={"color": "#00FF00"},
                    )

                continue

        # If not rerun the analyzer
        try:
            job = cortex_api.analyzers.run_by_name(
                analyzer.name,
                {"data": ioc, "dataType": ioc_type, "tlp": 1},
                force=1,
            )
            while job.status not in ["Success", "Failure"]:
                time.sleep(10)
                job = cortex_api.jobs.get_report(job.id)

            if job.status == "Success":
                response = job.json()
                try:
                    taxonomies = glom(
                        response, ("report.summary.taxonomies", ["level"])
                    )
                except PathAccessError:
                    taxonomies = None

                report = Report(
                    response=response,
                    content_object=db_object,
                    analyzer=analyzer,
                    taxonomies=taxonomies,
                    success=True,
                )
                report.save()

                if "malicious" in taxonomies:
                    db_object.tags.add(
                        "{}: malicious".format(analyzer.name),
                        tag_kwargs={"color": "#FF0000"},
                    )

                elif "suspicious" in taxonomies:
                    db_object.tags.add(
                        "{}: suspicious".format(analyzer.name),
                        tag_kwargs={"color": "#C15808"},
                    )

                elif "safe" in taxonomies:
                    db_object.tags.add(
                        "{}: safe".format(analyzer.name),
                        tag_kwargs={"color": "#00FF00"},
                    )

            elif job.status == "Failure":
                report = Report(
                    content_object=db_object,
                    analyzer=analyzer,
                    success=False,
                )
                report.save()

        except Exception as excp:
            logging.error(
                "ERROR running analyzer {} for {}: {}".format(analyzer.name, ioc, excp)
            )


@celery_app.task(name="process_mail")
def process_mail(content):
    """
    Single mail task
    """
    # IF PARSE FAILS IGNORE
    try:
        content = content.encode("utf_8")
        filepath = store_mail(content)
        msg = mailparser.parse_from_bytes(content)
    except Exception as e:
        logging.error(e)
        return "Error parsing mail"

    info, _, cortex_api = get_info(mail=False)

    methmail = MethMail(
        msg,
        info=info,
        cortex_api=cortex_api,
        mail_filepath=filepath,
    )
    subtasks = methmail.process_mail()

    if not subtasks:
        return "Error during processing"

    for (ioc, ioc_type, object_id, is_mail) in subtasks:
        check_cortex.apply_async(args=[ioc, ioc_type, object_id, is_mail])

    return "{} query run on cortex".format(len(subtasks))


@celery_app.task(name="check_mails", soft_time_limit=1800, time_limit=3600)
def check_mails():
    """
    Check if info are set and cortex is up.
    If yes reads new mails and runs subtasks
    """
    _, inbox, cortex_api = get_info()

    _, data = inbox.search(None, "(UNSEEN)")
    email_list = list(data[0].split())
    data_list = []
    for number in email_list:
        _, data = inbox.fetch(number, "(RFC822)")
        data_list.append(data[0][1])
    inbox.close()
    inbox.logout()

    for content in data_list:
        process_mail.apply_async(args=[content])

    return "{} mails found".format(len(data_list))
