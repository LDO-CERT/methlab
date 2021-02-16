import os
import json
import shutil
import pathlib
import uuid
import spf
import datetime
import mailparser
import magic
import hashlib
import whois
import dns.resolver
import logging

from django.db import transaction
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder

from zipfile import ZipFile, is_zipfile

import dkim
from ipwhois import IPWhois
from dateutil.parser import parse
from tld import get_fld
from checkdmarc import check_domains, results_to_json

from ip2geotools.databases.noncommercial import DbIpCity

from ioc_finder import (
    parse_urls,
    parse_ipv4_addresses,
    parse_ipv4_cidrs,
    parse_ipv6_addresses,
    parse_email_addresses,
)

from methlab.shop.models import (
    Mail,
    Attachment,
    Address,
    Ioc,
    Mail_Addresses,
    Whitelist,
)


def default(o):
    """helpers to store item in json

    arguments:
    - o: field of the object to serialize

    returns:
    - valid serialized value for unserializable fields
    """
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()
    if isinstance(o, set):
        return list(o)


class MethMail:
    def __init__(self, msg, info, cortex_api, mail_filepath, parent_id=None):
        """
        MethMail main mail class
        arguments:
        - msg: mail object
        - info: info regarding whitelist and vip
        - cortex_api: object to connect to cortex
        - mail_filepath: phisycal path of the mail
        - parent_id: parent id of the mail if processed mail was an attachment
        """
        self.msg = msg
        self.info = info
        self.cortex_api = cortex_api
        self.mail_filepath = mail_filepath
        self.parent_id = parent_id
        self.db_mail = None  # mail object in db
        self.tasks = []

    def process_mail(self):
        """Main workflow for single mail."""

        # IF MAIL WAS ALREADY PROCESSED CLEAN AND IGNORE
        try:
            old_mail = Mail.objects.get(
                message_id=self.msg.message_id, parent_id__pk=self.parent_id
            )
            self.clean_files((self.mail_filepath))
            del old_mail
            logging.warning("Mail already present in db - SKIPPING")
            return {
                "tasks": None,
                "ignore": True,
                "error": "Mail already present in db - SKIPPING",
            }
        except Mail.DoesNotExist:
            pass

        # CREATE OBJECT IN DB, returns PK or None if failed
        stored = self.store_info()
        if not stored["id"]:
            return {
                "tasks": None,
                "ignore": stored["ignore"],
                "error": stored["error"],
            }

        # ANALYZERS ON FULL EMAIL
        self.tasks.append((self.mail_filepath, "file", self.db_mail.pk, True))

        # Save attachments
        try:
            random_path = self.store_attachments()
            self.db_mail.attachments_path = random_path
            self.db_mail.save()
            logging.warning("Attachments path: {}".format(random_path))

            # PROCESS ATTACHMENTS
            for mess_att in self.msg.attachments:
                filepath = os.path.join(random_path, mess_att["filename"])
                logging.warning("Attachment written at {}".format(filepath))

                # I don't have payload or I don't understand type skip
                if not mess_att["mail_content_type"] or not mess_att["payload"]:
                    self.clean_files((filepath))
                    continue

                self.process_attachment(filepath, mess_att)
        except Exception as e:
            logging.error("Error processing attachments. {} - SKIPPING".format(e))
            return {
                "tasks": None,
                "ignore": False,
                "error": e,
            }

        return {
            "tasks": self.tasks,
            "ignore": False,
            "error": False,
        }

    def find_ioc(self, payload):
        """Extracts url and ip from text.

        arguments:
        - payload: message body
        """
        all_wl = Whitelist.objects.all()

        # EXTRACT URL, CHECK IF WL AND GET REPORT
        for url in parse_urls(payload):
            whois_info = None
            url = url.split(">")[0].rstrip('"].').strip("/").lower()
            domain = get_fld(url, fix_protocol=True, fail_silently=True)
            if domain in [x.value for x in all_wl if x.type == "domain"]:
                continue
            with transaction.atomic():
                if domain:
                    ioc, created = Ioc.objects.get_or_create(
                        domain=domain,
                    )
                else:
                    ioc, created = Ioc.objects.get_or_create(
                        url=url,
                    )
                if created:
                    try:
                        whois_info = json.loads(
                            json.dumps(
                                whois.query(domain).__dict__,
                                cls=DjangoJSONEncoder,
                                default=default,
                            )
                        )
                    except Exception:
                        pass

                if ioc.urls and url not in ioc.urls:
                    ioc.urls.append(url)
                elif not ioc.urls:
                    ioc.urls = [url]
                ioc.whois = whois_info
                ioc.save()
                self.db_mail.iocs.add(ioc)
                self.tasks.append((url, "url", ioc.pk, False))

        # EXTRACT IP, CHECK IF WL AND GET REPORT
        for ip in (
            parse_ipv4_addresses(payload)
            + parse_ipv4_cidrs(payload)
            + parse_ipv6_addresses(payload)
        ):
            whois_info = None
            if ip in [x.value for x in all_wl if x.type == "ip"]:
                continue

            with transaction.atomic():
                ioc, created = Ioc.objects.get_or_create(ip=ip)
                if created:
                    try:
                        whois_info = IPWhois(ip).lookup_rdap(depth=1)
                    except Exception:
                        pass

                ioc.whois = whois_info
                ioc.save()
            self.db_mail.iocs.add(ioc)
            self.tasks.append((ip, "ip", ioc.pk, False))

    def store_info(self):
        """Clean mail fields and create item in db"""
        with transaction.atomic():
            flags = []
            addresses_list = []

            mail_wl = Whitelist.objects.filter(type="address")

            geo_info = None
            dmark_info = None
            dkim_info = False
            spf_info = None

            # CHECK FROM ADDRESSES AND ASSIGN FLAGS
            for (name, address_from) in self.msg.from_:

                # if address is not valid skip object
                if address_from == "":
                    continue

                name = name.capitalize()
                address_from = address_from.lower()

                # if address in wl clean and skip
                if address_from in [x.value for x in mail_wl]:
                    self.clean_files((self.mail_filepath))
                    logging.warning("From address in whitelist - SKIPPING")
                    return {
                        "id": None,
                        "ignore": True,
                        "error": "From address in whitelist - SKIPPING",
                    }

                address, _ = Address.objects.get_or_create(address=address_from)

                # address could have multiple names
                if not address.name:
                    address.name = [name]
                elif name not in address.name:
                    address.name.append(name)

                # MX check on address domain
                address.domain = address_from.split("@")[-1]
                try:
                    address.mx_check = "\n".join(
                        [
                            "{}: {}".format(rdata.exchange, rdata.preference)
                            for rdata in dns.resolver.resolve(address.domain, "MX")
                        ]
                    )
                except Exception:
                    pass
                address.save()

                # Check fake names and vip scam
                # if there is an email in the mail name and is different from mail address
                addresses_list.append((address, "from"))
                other_addresses = parse_email_addresses(name)
                if len(other_addresses) > 0 and any(
                    [x != address_from for x in other_addresses]
                ):
                    flags.append("Fake Real Name")
                if self.info.vip_list:
                    for vip in self.info.vip_list:
                        if (
                            name.find(vip) != -1
                            and address_from.find(self.info.vip_domain) == -1
                        ):
                            flags.append("VIP SCAM")

            # clean TO, BCC, CC and REPLY_TO fields
            for (field_value, field_name) in zip(
                [self.msg.to, self.msg.bcc, self.msg.cc, self.msg.reply_to],
                ["to", "bcc", "cc", "reply_to"],
            ):
                for (name, address_value) in field_value:
                    if address_value == "":
                        continue
                    name = name.capitalize()
                    address_value = address_value.lower()
                    address, _ = Address.objects.get_or_create(address=address_value)
                    if not address.name:
                        address.name = [name]
                    elif name not in address.name:
                        address.name.append(name)
                    address.domain = address_value.split("@")[-1]
                    address.save()
                    addresses_list.append((address, field_name))

            # CHECK SPF & INTERNAL FROM FIRST HOP & GET MAP COORDINATES
            first_hop = next(iter(self.msg.received), None)
            if first_hop:
                ip = parse_ipv4_addresses(first_hop.get("from", []))
                domain = first_hop.get("by", None)

                if len(ip) > 0 and domain:
                    ip = ip[0]
                    try:
                        geo_info_json = json.loads(
                            DbIpCity.get(ip, api_key="free").to_json()
                        )
                        geo_info = {
                            "type": "Point",
                            "coordinates": [
                                geo_info_json["longitude"],
                                geo_info_json["latitude"],
                            ],
                        }
                    except Exception:
                        pass

                    try:
                        dmark_result = results_to_json(check_domains(domain))
                        dmark_info = (
                            dmark_result if dmark_result not in [[], "[]"] else None
                        )
                    except Exception:
                        pass

                    with open(self.mail_filepath, "rb") as f:
                        message = f.read()
                        dkim_info = dkim.DKIM(message).verify()

                    # SPF CHECK
                    domain = domain.split()[0]
                    sender = self.msg.from_[0][1]
                    result, explanation = spf.check2(s=sender, i=ip, h=domain)
                    if result != 250:
                        flags.append("SPF")
                        spf_info = "Sender {0} rejected on {1} ({2}): {3}. Considered Hop: {4}".format(
                            sender,
                            domain,
                            ip,
                            explanation,
                            first_hop,
                        )
                if (
                    domain
                    and self.info.internal_domains
                    and any(
                        [
                            domain.find(internal) != -1
                            for internal in self.info.internal_domains
                        ]
                    )
                ):
                    flags.append("Internal")

            # DATE from mail, if error now()
            if not self.msg.date:
                date = timezone.now()
            else:
                date = parse(
                    "{} {}".format(self.msg.date, self.msg.timezone.replace(".", ":"))
                )

            self.db_mail = Mail.objects.create(
                parent=None if not self.parent_id else Mail(self.parent_id),
                message_id=self.msg.message_id,
                subject=self.msg.subject,
                date=date,
                submission_date=date
                if not self.parent_id
                else Mail(self.parent_id).date,
                received=self.msg.received,
                headers=self.msg.headers,
                text_plain=self.msg.text_plain,
                text_html=self.msg.text_html,
                text_not_managed=self.msg.text_not_managed,
                sender_ip_address=self.msg.get_server_ipaddress(domain)
                if domain
                else None,
                to_domains=self.msg.to_domains,
                geom=geo_info,
                dmark=dmark_info,
                dkim=dkim_info,
                spf=spf_info,
                # this is an .eml if parent is None otherwhise is the parent attachment folder
                eml_path=self.mail_filepath,
            )

            # ADD ADDRESSES TO MAIL, CHECK IF HONEYPOT OR SECINC
            for addr_item, addr_type in addresses_list:
                addr_obj = Mail_Addresses(
                    mail=self.db_mail, address=addr_item, field=addr_type
                )
                addr_obj.save()
                if addr_type == "to":
                    if (
                        self.info.security_emails
                        and addr_item.address in self.info.security_emails
                    ):
                        self.db_mail.tags.add("SecInc")
                    if self.info.honeypot_emails and any(
                        [
                            addr_item.address.endswith(x)
                            for x in self.info.honeypot_emails
                        ]
                    ):
                        self.db_mail.tags.add("Honeypot")
                elif addr_type == "cc":
                    if (
                        self.info.security_emails
                        and addr_obj.address in self.info.security_emails
                    ):
                        self.db_mail.tags.add("SecInc")

                # check from mail in not internal and not in wl
                elif addr_type == "from" and (
                    not self.info.internal_domains
                    or all(
                        [
                            addr_item.address.lower().find(x) == -1
                            for x in self.info.internal_domains
                        ]
                    )
                ):
                    self.tasks.append((addr_item.address, "mail", addr_item.pk, False))

            if self.db_mail.tags.count() == 0:
                self.db_mail.tags.add("Hunting")

            self.find_ioc(self.db_mail.text_html)
            self.find_ioc(self.db_mail.text_plain)
            self.find_ioc(self.db_mail.text_not_managed)

            # STORE FLAGS IN DB
            for flag in flags:
                self.db_mail.tags.add(flag)

            return {"id": self.db_mail.pk, "ignore": False, "error": False}

    def store_attachments(self):
        """Store attachment to disk.

        returns:
        - random_path: path on disk containing attachments
        """
        random_path = os.path.join("/wip", str(uuid.uuid4()))
        os.makedirs(random_path)
        self.msg.write_attachments(random_path)
        return random_path

    def clean_files(self, filepaths):
        """Clean a file or folder.

        arguments:
        - filepath: path to delete
        """
        try:
            for filepath in filepaths:
                if os.path.isdir(filepath):
                    shutil.rmtree(filepath)
                    logging.warning("Deleting folder {}".format(filepath))
                elif os.path.isfile(filepath):
                    os.remove(filepath)
                    logging.warning("Deleting path {}".format(filepath))
        except Exception as e:
            logging.error("Error deleting files {}. {}".format(filepaths, e))

    def is_whitelisted(self, content_type, mimetype_whitelist=None):
        """Checks if content_type is whitelisted.

        arguments:
        - content_type: attachment content type

        returns:
        - True: content_type is in whitelist
        - False: content_type is not in whitelist
        """

        if mimetype_whitelist:
            for wl in mimetype_whitelist:
                if content_type.startswith(wl):
                    return True
        return False

    def get_hashes(self, filepath):
        """Get file md5, sha1, sha256.

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
        return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()

    def process_attachment(self, filepath, mess_att):
        """Check if attachments is whitelisted, zipped, another mail or text:

        arguments:
        - filepath: path of the attachment
        - mess_att: attachment obcject
        """

        all_wl = Whitelist.objects.all()
        _, fileext = os.path.splitext(mess_att["filename"])
        fileext = fileext.lower()
        old_filepath = filepath

        if not os.path.exists(filepath):
            logging.error("Path {} does not exists - SKIPPING".format(filepath))
            return False

        # Unzip the attachment if is_zipfile
        if is_zipfile(filepath) and fileext not in [
            ".jar",
            ".xlsx",
            ".xlsm",
            ".docx",
            ".pptx",
        ]:
            with ZipFile(filepath, "r") as zipObj:
                objs = zipObj.namelist()
                if len(objs) == 1:
                    filepath = zipObj.extract(objs[0], pathlib.Path(filepath).parent)
                    mess_att["mail_content_type"] = magic.from_file(filepath, mime=True)
                else:
                    # Zipped and multiple files, skip
                    self.clean_files((filepath, old_filepath))
                    logging.warning(
                        "Zipped and multiple files in attachment - SKIPPING"
                    )
                    return False

        if self.is_whitelisted(
            mess_att["mail_content_type"], self.info.mimetype_whitelist
        ):
            self.clean_files((filepath, old_filepath))
            logging.warning("Attachment type in whitelist - SKIPPING")
            return False

        # IF MAIL PROCESS RECURSIVELY
        if mess_att["mail_content_type"] in [
            "application/ms-tnef",
            "Transport Neutral Encapsulation Format",
        ]:
            logging.warning("TNEF not supported")
        elif (
            mess_att["mail_content_type"] == "application/octet-stream"
            and fileext in (".eml", ".msg")
        ) or mess_att["mail_content_type"] == "message/rfc822":
            if fileext == ".msg":
                internal_message = mailparser.parse_from_file_msg(filepath)
            else:
                internal_message = mailparser.parse_from_file(filepath)
            internal_methmail = MethMail(
                internal_message,
                info=self.info,
                cortex_api=self.cortex_api,
                mail_filepath=filepath,
            )
            internal_methmail.process_mail()

        # IF TEXT EXTRACT IOC
        elif mess_att["mail_content_type"] in (
            "text/plain",
            "text/html",
        ):
            self.find_ioc(mess_att["payload"])

        # IF GENERIC FILE, EXTRACT MD5/SHA256 AND GET REPORT
        else:
            md5, sha1, sha256 = self.get_hashes(filepath)
            if md5 in [x.value for x in all_wl if x.type == "md5"] or sha256 in [
                x.value for x in all_wl if x.type == "sha256"
            ]:
                self.clean_files((filepath, old_filepath))
                logging.warning("Attachment hash in wl - SKIPPING")
                return False

            fix_mail_dict = dict((k.replace("-", "_"), v) for k, v in mess_att.items())
            filename = fix_mail_dict["filename"]
            del fix_mail_dict["payload"]
            del fix_mail_dict["filename"]
            with transaction.atomic():
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
                self.db_mail.attachments.add(attachment)
                # Check file in onprem sandboxes
                self.tasks.append((attachment.filepath, "file", attachment.pk, False))
                # Check hashes in cloud services
                self.tasks.append((attachment.sha256, "hash", attachment.pk, False))
