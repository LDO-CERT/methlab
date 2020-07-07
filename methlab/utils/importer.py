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

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")
django.setup()

from django.core.exceptions import ObjectDoesNotExist  # noqa
from django.contrib.contenttypes.models import ContentType  # noqa

from tqdm import tqdm  # noqa
from glom import glom, PathAccessError  # noqa

import shutil  # noqa
import pathlib  # noqa
import time  # noqa
import pytz  # noqa
import uuid  # noqa
import spf  # noqa
import mailparser  # noqa
import dateutil  # noqa
import magic  # noqa
import hashlib  # noqa
import whois  # noqa

# from ipwhois import IPWhois  # noqa
from tnefparse import TNEF  # noqa
from zipfile import ZipFile, is_zipfile  # noqa
from django.utils import timezone  # noqa
from imaplib import IMAP4  # noqa
from dateutil.parser import parse  # noqa
from tldextract import extract  # noqa
from cortex4py.api import Api  # noqa
from ip2geotools.databases.noncommercial import MaxMindGeoLite2City  # noqa

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
    Analyzer,
    Report,
    Whitelist,
)

import logging  # noqa

logging.basicConfig(filename="/app/methlab/importer.log", level=logging.DEBUG)

try:
    info = InternalInfo.objects.first()
    inbox = IMAP4(info.imap_server)
    inbox.starttls()
    inbox.login(info.imap_username, info.imap_password)
    inbox.select(info.imap_folder)
except ObjectDoesNotExist:
    logging.error("missing information")
    sys.exit()
except IMAP4.error:
    logging.error("error connecting to imap")
    sys.exit()

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
    """ Store attachment to disk.

        arguments:
        - msg: mail containing attachments

        returns:
        - random_path: path on disk containing attachments
    """
    random_path = "/tmp/{}".format(uuid.uuid4())
    os.makedirs(random_path)
    msg.write_attachments(random_path)
    logging.debug("storing attachment at {}".format(random_path))
    return random_path


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


def clean_file(filepath):
    """ Clean a file or log error.

        arguments:
        - filepath: path to delete
    """
    try:
        os.remove(filepath)
    except FileNotFoundError:
        logging.error("Error deleting {}".format(filepath))


def check_cortex(ioc, ioc_type, object_id, mail, is_mail=False):
    """ Run all available analyzer for ioc.

        arguments:
        - ioc: value/path of item we need to check on cortex
        - ioc_type: type of the ioc (generic_relation and cortex datatype)
        - object_id: item to attach report to
        - mail: original mail object to add tag if dangerous
        - is_mail: ioc is a mail [mail datatype is for addresses and file is for mail]

        returns:
        - True: item is dangerous
        - False: item is safe
     """

    # Mail object is file in cortex
    # need to save mail object analyzer as mail_obj to discriminate them
    filter_type = ioc_type if not is_mail else "mail_obj"
    analyzers = Analyzer.objects.filter(
        disabled=False, supported_types__contains=[filter_type]
    ).order_by("-priority")

    if ioc_type == "mail" and is_mail is False:
        content_type = Address
    elif ioc_type == "mail" and is_mail is True:
        content_type = Mail
    elif ioc_type in ["url", "ip"]:
        content_type = Ioc
    elif ioc_type == "file":
        content_type = Attachment
    else:
        logging.error("IOCTYPE {} not managed".format(ioc_type))
        return False

    old_reports = Report.objects.filter(
        content_type=ContentType.objects.get_for_model(content_type),
        object_id=object_id.pk,
        success=True,
    )

    for analyzer in analyzers:

        for report in old_reports:
            if report.analyzer == analyzer:
                logging.debug(
                    "Analyzer {} for {} already run".format(analyzer.name, ioc)
                )
                if "malicious" in report.taxonomies:
                    mail.tags.add("{}: malicious".format(analyzer.name))
                    return True
                elif "suspicious" in report.taxonomies:
                    mail.tags.add("{}: suspicious".format(analyzer.name))
                    return True
                continue

        logging.debug("running analyzer {} for {}".format(analyzer.name, ioc))
        try:
            job = cortex_api.analyzers.run_by_name(
                analyzer.name, {"data": ioc, "dataType": ioc_type, "tlp": 1}, force=1,
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
                    content_object=object_id,
                    analyzer=analyzer,
                    taxonomies=taxonomies,
                    success=True,
                )
                report.save()
                logging.debug("done analyzer {} for {}".format(analyzer.name, ioc))

                if "malicious" in taxonomies:
                    mail.tags.add("{}: malicious".format(analyzer.name))
                elif "suspicious" in taxonomies:
                    mail.tags.add("{}: suspicious".format(analyzer.name))

            elif job.status == "Failure":
                report = Report(
                    content_object=object_id, analyzer=analyzer, success=False,
                )
                report.save()
                logging.error(
                    "ERROR running analyzer {} for {}: {}".format(
                        analyzer.name, ioc, job.errorMessage
                    )
                )
        except Exception as excp:
            logging.error(
                "ERROR running analyzer {} for {}: {}".format(analyzer.name, ioc, excp)
            )


def get_hashes(filepath):
    """" Get file md5, sha1, sha256.

        arguments:
        - filepath: file to generate md5/sha1/sha256

        returns:
        - md5/sha1/sha256
    """

    with open(filepath, "rb") as f:
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    logging.debug("generating fingerprint for {}".format(filepath))
    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()


def is_whitelisted(content_type):
    """" Checks if content_type is whitelisted.

        arguments:
        - content_type: attachment content type

        returns:
        - True: content_type is in whitelist
        - False: content_type is not in whitelist
    """

    if info.mimetype_whitelist:
        for wl in info.mimetype_whitelist:
            if content_type.startswith(wl):
                logging.debug("{} is whitelisted".format(content_type))
                return True
    return False


def process_tnef(filepath, parent_id=None):
    """ Tnef is like an email but parser is different.

        arguments:
        - filepath: path of the tnef file
        - parend_id: id of the parent mail

        returns:
        - True: tnef email is dangerous
        - False: tnef email is safe
    """

    with open(filepath, "rb") as tneffile:
        tnef = TNEF(tneffile.read())

    tnef_objects = getattr(tnef, "objects", [])
    for tnef_object in tnef_objects:
        descriptive_name = TNEF.codes.get(tnef_object.name)
        try:
            object_data = tnef_object.data.strip(b"\0") or None
        except Exception:
            object_data = tnef_object.data

        subject = dateobj = message_id = None
        if object_data:
            if descriptive_name == "Subject":
                subject = object_data
            elif descriptive_name == "Date Sent":
                dateobj = object_data
            elif descriptive_name == "Message ID":
                message_id = object_data
    body = None
    tnef_html = getattr(tnef, "htmlbody", None)
    tnef_rtf = getattr(tnef, "rtfbody", None)
    if tnef_html:
        body = tnef_html
    elif tnef_rtf:
        body = tnef_rtf

    mail = Mail(
        parent=None if not parent_id else Mail(parent_id),
        message_id=message_id,
        subject=subject,
        date=dateobj,
        body=body,
    )
    mail.save()

    tnef_attachments = getattr(tnef, "attachments", [])
    if tnef_attachments:
        random_path = "/tmp/{}".format(uuid.uuid4())
        os.makedirs(random_path)

    for attachment in tnef_attachments:
        attachment_name = attachment.name.decode() if attachment.name else uuid.uuid4()

        filepath = "{}/{}".format(random_path, attachment_name)

        with open(filepath, "wb") as f:
            f.write(attachment.data)

        attachment_magic = magic.from_file(filepath, mime=True)

        if is_whitelisted(attachment_magic):
            clean_file(filepath)
            continue

        mess_att = {"mail_content_type": attachment_magic, "payload": attachment.data}

        if process_attachment(filepath, mail, mess_att, parent_id):
            return True
    return False


def process_attachment(filepath, mail, mess_att, parent_id):
    """ Check if attachments is whitelisted, zipped, another mail or text:

        arguments:
        - filepath: path of the attachment
        - mail: mail object attachment is related to
        - mess_att: attachment obcject
        - parent_id: parent_id to propagate from mail if attachment is an mail

        returns:
        - True: attachment is dangerous
        - False: attachment is safe
    """

    all_wl = Whitelist.objects.all()
    _, fileext = os.path.splitext(mess_att["filename"])
    fileext = fileext.lower()

    if not os.path.exists(filepath):
        logging.error("ERROR: {} does not exists".format(filepath))
        return False

    # Unzip the attachment if is_zipfile
    if is_zipfile(filepath) and fileext not in ["jar", "xlsx", "xlsm", "docx"]:
        with ZipFile(filepath, "r") as zipObj:
            objs = zipObj.namelist()
            if len(objs) == 1:
                filepath = zipObj.extract(objs[0], pathlib.Path(filepath).parent)
                mess_att["mail_content_type"] = magic.from_file(filepath, mime=True)
                logging.debug("ATTACHMENT unzipped, new path {}".format(filepath))
            else:
                # Zipped and multiple files, skip
                logging.error(
                    "ATTACHMENT {} is zipped but with more than 1 file - {}".format(
                        filepath, fileext
                    )
                )
                clean_file(filepath)
                return False

    if is_whitelisted(mess_att["mail_content_type"]):
        clean_file(filepath)
        return False

    # IF MAIL PROCESS RECURSIVELY
    if mess_att["mail_content_type"] in [
        "application/ms-tnef",
        "Transport Neutral Encapsulation Format",
    ]:
        logging.debug("ATTACHMENT {} is a tnef, parsing".format(filepath))
        process_tnef(filepath, parent_id=parent_id)
    elif (
        mess_att["mail_content_type"] == "application/octet-stream"
        and fileext in (".eml", ".msg")
    ) or mess_att["mail_content_type"] == "message/rfc822":
        if fileext == ".msg":
            internal_message = mailparser.parse_from_file_msg(filepath)
        else:
            internal_message = mailparser.parse_from_file(filepath)
        logging.debug("ATTACHMENT {} is a mail, parsing".format(filepath))
        process_mail(internal_message, mail.pk, filepath)

    # IF TEXT EXTRACT IOC
    elif mess_att["mail_content_type"] in ("text/plain", "text/html",):
        logging.debug("ATTACHMENT {} is text, extracting ioc".format(filepath))
        find_ioc(mess_att["payload"], mail)

    # IF GENERIC FILE, EXTRACT MD5/SHA256 AND GET REPORT
    else:
        logging.debug("ATTACHMENT {} is file, sending to cortex".format(filepath))
        md5, sha1, sha256 = get_hashes(filepath)
        if md5 in [x.value for x in all_wl if x.type == "md5"] or sha256 in [
            x.value for x in all_wl if x.type == "sha256"
        ]:
            clean_file(filepath)
            return False

        fix_mail_dict = dict((k.replace("-", "_"), v) for k, v in mess_att.items())
        filename = fix_mail_dict["filename"]
        del fix_mail_dict["payload"]
        del fix_mail_dict["filename"]
        attachment, created = Attachment.objects.get_or_create(
            md5=md5, defaults=fix_mail_dict
        )
        if created:
            attachment.filename = [filename]
            attachment.filepath = filepath
            attachment.sha1 = sha1
            attachment.sha256 = sha256
        else:
            if filename not in attachment.filename:
                attachment.filename.append(filename)
        attachment.save()
        mail.attachments.add(attachment)
        if check_cortex(filepath, "file", attachment, mail):
            return True

    # Attachment is safe
    return False


def find_ioc(payload, mail):
    """" Extracts url and ip from text.

        arguments:
        - payload: message body
        - mail: mail item

        returns:
        - True: some iocs are dangerous
        - False: all iocs are safe
    """

    all_wl = Whitelist.objects.all()

    # EXTRACT URL, CHECK IF WL AND GET REPORT
    for url in parse_urls(payload):
        whois_info = None
        url = url.split(">")[0].rstrip('"].').strip("/").lower()
        domain = ".".join(part for part in extract(url) if part)
        if domain in [x.value for x in all_wl if x.type == "domain"]:
            logging.debug("IOC url: {} WL".format(url))
            continue
        ioc, created = Ioc.objects.get_or_create(domain=domain,)
        if created:
            whois_info = whois.query(domain)

        if ioc.urls and url not in ioc.urls:
            ioc.urls.append(url)
            ioc.whois = whois_info
            ioc.save()
        elif not ioc.urls:
            ioc.urls = [url]
            ioc.save()
        mail.iocs.add(ioc)
        if check_cortex(url, "url", ioc, mail):
            return True

    # EXTRACT IP, CHECK IF WL AND GET REPORT
    for ip in (
        parse_ipv4_addresses(payload)
        + parse_ipv4_cidrs(payload)
        + parse_ipv6_addresses(payload)
    ):
        whois_info = None
        if ip in [x.value for x in all_wl if x.type == "ip"]:
            logging.debug("IOC ip: {} WL".format(ip))
            continue
        ioc, created = Ioc.objects.get_or_create(ip=ip)
        # if created:
        # whois_info = IPWhois(ip).lookup_rdap(depth=1)
        ioc.whois = whois_info
        ioc.save()
        mail.iocs.add(ioc)
        if check_cortex(ip, "ip", ioc):
            return True

    # All IOC as ok, return False
    return False


def process_mail(msg, parent_id=None, mail_filepath=None):
    """ Main workflow for single mail.

        arguments:
        - msg: mail object
        - parent_id: parent id of the mail if processed mail was an attachment
        - mail_filepath: phisycal path of the mail

        returns:
        - None
    """

    # IF MAIL WAS ALREADY PROCESSED IGNORE
    try:
        mail = Mail.objects.get(message_id=msg.message_id, parent_id__pk=parent_id)
        logging.error("mail already in db - skip")
        return
    except Mail.DoesNotExist:
        pass

    flags = []

    mail_wl = Whitelist.objects.filter(type="address")

    geo_info = None

    # CHECK ADDRESSES AND ASSIGN FLAGS
    addresses_list = []
    for (name, address_from) in msg.from_:
        name = name.capitalize()
        address_from = address_from.lower()
        if address_from in [x.value for x in mail_wl]:
            logging.debug("sender {} in WL - skip".format(address_from))
            return
        address, _ = Address.objects.get_or_create(address=address_from)
        if not address.name:
            address.name = [name]
        elif name not in address.name:
            address.name.append(name)
        address.domain = address_from.split("@")[-1]
        address.save()
        addresses_list.append((address, "from"))
        other_addresses = parse_email_addresses(name)
        if len(other_addresses) > 0 and any(
            [x != address_from for x in other_addresses]
        ):
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

    for (name, address_to) in msg.to:
        name = name.capitalize()
        address_to = address_to.lower()
        address, _ = Address.objects.get_or_create(address=address_to)
        if not address.name:
            address.name = [name]
        elif name not in address.name:
            address.name.append(name)
        address.domain = address_to.split("@")[-1]
        address.save()
        addresses_list.append((address, "to"))

    for (name, address_bcc) in msg.bcc:
        name = name.capitalize()
        address_bcc = address_bcc.lower()
        address, _ = Address.objects.get_or_create(address=address_bcc)
        if not address.name:
            address.name = [name]
        elif name not in address.name:
            address.name.append(name)
        address.domain = address_bcc.split("@")[-1]
        address.save()
        addresses_list.append((address, "bcc"))

    for (name, address_cc) in msg.cc:
        name = name.capitalize()
        address_cc = address_cc.lower()
        address, _ = Address.objects.get_or_create(address=address_cc)
        if not address.name:
            address.name = [name]
        elif name not in address.name:
            address.name.append(name)
        address.domain = address_cc.split("@")[-1]
        address.save()
        addresses_list.append((address, "cc"))

    for (name, address_reply_to) in msg.reply_to:
        name = name.capitalize()
        address_reply_to = address_reply_to.lower()
        address, _ = Address.objects.get_or_create(address=address_reply_to)
        if not address.name:
            address.name = [name]
        elif name not in address.name:
            address.name.append(name)
        address.domain = address_reply_to.split("@")[-1]
        address.save()
        addresses_list.append((address, "reply_to"))

    # CHECK SPF & INTERNAL FROM FIRST HOP
    first_hop = next(iter(msg.received), None)
    if first_hop:
        from pprint import pprint

        pprint(first_hop)

        ip = parse_ipv4_addresses(first_hop.get("from", []))
        domain = first_hop.get("by", None)

        if len(ip) > 0 and domain:
            ip = ip[0]
            try:
                geo_info = MaxMindGeoLite2City.get(ip, api_key="free").to_json()
            except Exception as e:
                logging.error(e)
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
            and any([domain.find(internal) != -1 for internal in info.internal_domains])
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
        body=msg.body,
        sender_ip_address=msg.get_server_ipaddress(info.imap_server),
        to_domains=msg.to_domains,
        geo_info=geo_info,
    )
    mail.save()

    # RUN ANALYZERS ON FULL EMAIL
    if check_cortex(mail_filepath, "file", mail, mail, is_mail=True):
        return

    for addr_item, addr_type in addresses_list:

        # RUN ANALYZERS ON EMAIL ADDRESSES
        if not info.internal_domains or all(
            [addr_item.address.lower().find(x) == -1 for x in info.internal_domains]
        ):
            if check_cortex(addr_item.address, "mail", addr_item, mail, is_mail=False):
                return

        addr_obj = Mail_Addresses(mail=mail, address=addr_item, field=addr_type)
        addr_obj.save()
        if addr_type == "to":
            if info.security_emails and addr_item.address in info.security_emails:
                mail.tags.add("SecInc")
            if info.honeypot_emails and any(
                [addr_item.address.endswith(x) for x in info.honeypot_emails]
            ):
                mail.tags.add("Honeypot")
        elif addr_type == "cc":
            if info.security_emails and addr_obj.address in info.security_emails:
                mail.tags.add("SecInc")
    if mail.tags.count() == 0:
        mail.tags.add("Hunting")

    # STORE FLAGS IN DB
    for flag, note in flags:
        mf = Mail_Flag(mail=mail, flag=flag, note=note)
        mf.save()

    if find_ioc(mail.body, mail):
        return

    # Save attachments
    random_path = store_attachments(msg)

    # PROCESS ATTACHMENTS
    for mess_att in msg.attachments:

        filepath = "{}/{}".format(random_path, mess_att["filename"])

        # I don't have payload or I don't understand type skip
        if not mess_att["mail_content_type"] or not mess_att["payload"]:
            clean_file(filepath)
            continue

        if process_attachment(filepath, mail, mess_att, parent_id):
            return

    # DELETE MAIL TEMP FILE
    clean_file(mail_filepath)


def main():
    """ check mails in inbox - main loop """

    clean = True
    if clean:
        Address.objects.all().delete()
        Ioc.objects.all().delete()
        Mail.objects.all().delete()
        Report.objects.all().delete()
        Attachment.objects.all().delete()
        [
            shutil.rmtree("/tmp/{}".format(x))
            for x in os.listdir("/tmp")
            if os.path.isdir(x)
        ]
        [
            os.remove("/tmp/{}".format(x))
            for x in os.listdir("/tmp")
            if os.path.isfile(x)
        ]

        _, data = inbox.search(None, "(ALL)")
    else:
        _, data = inbox.search(None, "(UNSEEN)")

    email_list = list(data[0].split())
    for number in tqdm(email_list):
        _, data = inbox.fetch(number, "(RFC822)")

        # IF PARSE FAILS IGNORE
        try:
            content = data[0][1]
            filepath = store_mail(content)
            msg = mailparser.parse_from_bytes(content)
        except Exception as e:
            logging.error(e)
            continue
        logging.debug("PARSING MAIL {}".format(number))
        process_mail(msg, mail_filepath=filepath)


if __name__ == "__main__":
    main()
