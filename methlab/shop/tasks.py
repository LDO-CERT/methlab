import uuid
import time
import logging
import datetime

import kombu

import socket
import mailparser
from imaplib import IMAP4

from config import celery_app
from glom import glom, PathAccessError
from tld.utils import update_tld_names


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
    Ip,
    Url,
    Domain,
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
    eml_path = "/wip/{}.eml".format(uuid.uuid4())
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


@celery_app.task(name="check_cortex", soft_time_limit=960, time_limit=1800)
def check_cortex(ioc, ioc_type, object_id, is_mail=False, cortex_expiration_days=30):
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

    # Full mail only on premise
    if ioc_type == "file":
        analyzers = analyzers.filter(onpremise=True)
        if is_mail is True:
            content_type = Mail
        else:
            content_type = Attachment

    elif ioc_type == "mail":
        content_type = Address

    elif ioc_type == "url":
        content_type = Url

    elif ioc_type == "domain":
        content_type = Domain

    elif ioc_type == "ip":
        content_type = Ip

    elif ioc_type == "hash":
        content_type = Attachment

    else:
        logging.error("Wrong ioc_type type {}".format(ioc_type))
        return

    old_reports = Report.objects.filter(
        content_type=ContentType.objects.get_for_model(content_type),
        object_id=object_id,
        success=True,
        date__gte=datetime.datetime.today()
        - datetime.timedelta(days=cortex_expiration_days),
    )

    try:
        db_object = content_type.objects.get(pk=object_id)
    except Exception:
        logging.error("CORTEX {} {} {} {}".format(ioc, ioc_type, object_id, is_mail))
        return

    for analyzer in analyzers:

        # Check if item was already been processed
        for report in old_reports:
            if report.analyzer == analyzer:
                if "malicious" in report.taxonomies:
                    db_object.tags.add(
                        "{}: malicious".format(analyzer.name),
                        tag_kwargs={"color": "#FF0000"},
                    )
                    db_object.taxonomy = 4
                    db_object.save()

                elif "suspicious" in report.taxonomies:
                    db_object.tags.add(
                        "{}: suspicious".format(analyzer.name),
                        tag_kwargs={"color": "#C15808"},
                    )
                    db_object.taxonomy = max(3, db_object.taxonomy)
                    db_object.save()

                elif "safe" in report.taxonomies:
                    db_object.tags.add(
                        "{}: safe".format(analyzer.name),
                        tag_kwargs={"color": "#00FF00"},
                    )
                    db_object.taxonomy = max(2, db_object.taxonomy)
                    db_object.save()

                elif "info" in report.taxonomies:
                    db_object.tags.add(
                        "{}: info".format(analyzer.name),
                        tag_kwargs={"color": "#00B0FF"},
                    )
                    db_object.taxonomy = max(1, db_object.taxonomy)
                    db_object.save()

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
                    db_object.taxonomy = 4
                    db_object.save()

                elif "suspicious" in taxonomies:
                    db_object.tags.add(
                        "{}: suspicious".format(analyzer.name),
                        tag_kwargs={"color": "#C15808"},
                    )
                    db_object.taxonomy = max(3, db_object.taxonomy)
                    db_object.save()

                elif "safe" in taxonomies:
                    db_object.tags.add(
                        "{}: safe".format(analyzer.name),
                        tag_kwargs={"color": "#00FF00"},
                    )
                    db_object.taxonomy = max(2, db_object.taxonomy)
                    db_object.save()

                elif "info" in taxonomies:
                    db_object.tags.add(
                        "{}: info".format(analyzer.name),
                        tag_kwargs={"color": "#00B0FF"},
                    )
                    db_object.taxonomy = max(1, db_object.taxonomy)
                    db_object.save()

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

    return True


@celery_app.task(name="process_mail", soft_time_limit=960, time_limit=1800)
def process_mail(content, filetype, parent_id):
    """
    Single mail task
    """
    # IF PARSE FAILS IGNORE
    if filetype == None:
        try:
            content = content.encode("utf_8")
            filepath = store_mail(content)
            msg = mailparser.parse_from_bytes(content)
        except Exception as e:
            logging.error(e)
            return "Error parsing mail from mail server: {}".format(e)

    elif filetype == ".msg":
        try:
            msg = mailparser.parse_from_file_msg(content)
            filepath = content
        except Exception as e:
            logging.error(e)
            return "Error parsing mail from msg attachment: {}".format(e)

    else:
        try:
            msg = mailparser.parse_from_file(content)
            filepath = content
        except Exception as e:
            logging.error(e)
            return "Error parsing mail from eml attachment: {}".format(e)

    info, _, cortex_api = get_info(mail=False)

    methmail = MethMail(
        msg,
        info=info,
        cortex_api=cortex_api,
        mail_filepath=filepath,
        parent_id=parent_id,
    )
    subtasks = methmail.process_mail()

    # Errors must be raise
    if not subtasks["ignore"] and subtasks["error"]:
        logging.error(subtasks["error"])
        raise Exception(subtasks["error"])

    # ignored are ok
    elif subtasks["ignore"]:
        return subtasks["error"]

    if subtasks["tasks"]:
        for (ioc, ioc_type, object_id, is_mail) in subtasks["tasks"]:
            check_cortex.apply_async(
                args=[ioc, ioc_type, object_id, is_mail, info.cortex_expiration_days]
            )

    if subtasks["childs"] and subtasks["id"]:
        for filepath, fileext in subtasks["childs"]:
            process_mail.apply_async(args=[filepath, fileext, subtasks["id"]])

    return "{} query run on cortex".format(len(subtasks))


@celery_app.task(name="check_mails", soft_time_limit=1800, time_limit=3600)
def check_mails():
    """
    Check if info are set and cortex is up.
    If yes reads new mails and runs subtasks
    """
    _, inbox, _ = get_info()

    _, data = inbox.search(None, "(UNSEEN)")
    email_list = list(data[0].split())
    data_list = []
    for number in email_list:
        _, data = inbox.fetch(number, "(RFC822)")
        data_list.append(data[0][1])
    inbox.close()
    inbox.logout()

    for content in data_list:
        try:
            process_mail.apply_async(args=[content, None, None])
        except kombu.exceptions.EncodeError:
            process_mail.apply_async(
                args=[content.decode("utf8", "ignore").encode("utf8"), None, None]
            )

    return "{} mails found".format(len(data_list))


@celery_app.task(name="update_tld")
def update_tld():
    """
    Update tld
    """
    update_tld_names()
