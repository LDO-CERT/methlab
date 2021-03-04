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
import asyncwhois
import dns.resolver
import logging

from django.db import transaction
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder

from zipfile import ZipFile, is_zipfile

import dkim
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
    Ip,
    Url,
    Domain,
    Mail_Addresses,
    Whitelist,
)


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
        self.id = None
        self.msg = msg
        self.info = info
        self.cortex_api = cortex_api
        self.mail_filepath = mail_filepath
        self.parent_id = parent_id
        self.db_mail = None  # mail object in db
        self.tasks = []
        self.childs = []

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
                "id": None,
                "tasks": None,
                "childs": None,
                "ignore": True,
                "error": "Mail already present in db - SKIPPING",
            }
        except Mail.DoesNotExist:
            pass

        # CREATE OBJECT IN DB, returns PK or None if failed
        stored = self.store_info()
        if not stored["id"]:
            return {
                "id": None,
                "tasks": None,
                "childs": None,
                "ignore": stored["ignore"],
                "error": stored["error"],
            }

        # ANALYZERS ON FULL EMAIL
        self.tasks.append((self.mail_filepath, "file", self.db_mail.pk, True))

        # Save attachments
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
                self.clean_files((filepath,))
                continue

            self.process_attachment(filepath, mess_att)
        return {
            "id": self.db_mail.pk,
            "tasks": self.tasks,
            "childs": self.childs,
            "ignore": False,
            "error": False,
        }

    def find_ioc(self, payload):
        """Extracts url and ip from text.

        arguments:
        - payload: message body
        """
        all_wl = Whitelist.objects.all()

        whois_list = []

        # EXTRACT URL, CHECK IF WL AND GET REPORT
        for url_value in parse_urls(payload):
            whois_info = None
            url_value = url_value.split(">")[0].rstrip('"].').strip("/").lower()
            if url_value in [x.value for x in all_wl if x.type == "url"]:
                continue
            url_domain = get_fld(url_value, fix_protocol=True, fail_silently=True)
            if url_domain in [x.value for x in all_wl if x.type == "domain"]:
                continue
            with transaction.atomic():
                if url_domain:
                    domain, created = Domain.objects.get_or_create(domain=url_domain)
                    if created:
                        whois_list.append((domain, domain.domain))
                else:
                    domain = None
                url, created = Url.objects.get_or_create(domain=domain, url=url_value)
                self.db_mail.urls.add(url)
                self.tasks.append((url_value, "url", url.pk, False))

        # EXTRACT IP, CHECK IF WL AND GET REPORT
        for ip_value in (
            parse_ipv4_addresses(payload)
            + parse_ipv4_cidrs(payload)
            + parse_ipv6_addresses(payload)
        ):
            whois_info = None
            if ip_value in [x.value for x in all_wl if x.type == "ip"]:
                continue

            with transaction.atomic():
                ip, created = Ip.objects.get_or_create(ip=ip_value)
                if created:
                    whois_list.append((ip, ip.ip))

                ip.whois = whois_info
                ip.save()
            self.db_mail.ips.add(ip)
            self.tasks.append((ip_value, "ip", ip.pk, False))

        for item, value in whois_list:
            try:
                item.whois = json.loads(
                    json.dumps(
                        asyncwhois.lookup(value).parser_output, cls=DjangoJSONEncoder
                    )
                )
                item.save()
            except Exception as e:
                logging.error("WHOIS ERROR {}".format(e))

    def store_info(self):
        """Clean mail fields and create item in db"""
        with transaction.atomic():
            flags = []
            addresses_list = []

            mail_wl = Whitelist.objects.filter(type="address")

            geo_info = None
            dmark_info = None
            dkim_info = None
            spf_info = None
            arc_info = None
            sender_ip = None

            # CHECK FROM ADDRESSES AND ASSIGN FLAGS
            for (name, address_from) in self.msg.from_:

                # if address is not valid skip object
                if address_from == "":
                    continue

                name = name.capitalize()
                address_from = address_from.lower()
                address_domain = address_from.split("@")[-1]

                # if address in wl clean and skip
                if address_from in [x.value for x in mail_wl]:
                    self.clean_files((self.mail_filepath,))
                    logging.warning("From address in whitelist - SKIPPING")
                    return {
                        "id": None,
                        "ignore": True,
                        "error": "From address in whitelist - SKIPPING",
                    }

                address, _ = Address.objects.get_or_create(
                    address=address_from, domain=address_domain
                )

                # address could have multiple names
                if not address.name:
                    address.name = [name]
                elif name not in address.name:
                    address.name.append(name)

                # MX check on address domain
                try:
                    address.mx_check = "\n".join(
                        [
                            "{}: {}".format(rdata.exchange, rdata.preference)
                            for rdata in dns.resolver.resolve(address.domain, "MX")
                        ]
                    )
                except Exception as e:
                    logging.error("MX DOMAIN ERROR {}".format(e))
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
                    address_domain = address_value.split("@")[-1]
                    address, _ = Address.objects.get_or_create(
                        address=address_value, domain=address_domain
                    )
                    if not address.name:
                        address.name = [name]
                    elif name not in address.name:
                        address.name.append(name)
                    address.save()
                    addresses_list.append((address, field_name))

            # CHECK DKIM READING EMAIL
            with open(self.mail_filepath, "rb") as f:
                message = f.read()
                try:
                    dkim_info = dkim.DKIM(message).verify()
                except dkim.DKIMException as e:
                    dkim_info = "{}".format(e)

            # CHECK ARC READING EMAIL
            try:
                success, info, arc_message = dkim.ARC(message).verify()
                if success == dkim.CV_Pass:
                    success = True
                elif success in [dkim.CV_Fail, dkim.CV_None]:
                    success = False
                arc_info = json.loads(
                    json.dumps(
                        {
                            "success": success,
                            "info": info,
                            "message": arc_message,
                        }
                    )
                )
            except Exception as e:
                logging.error("ARC ERROR {}".format(e))

            # CHECK SPF & INTERNAL FROM FIRST HOP & GET MAP COORDINATES
            first_hop = next(iter(self.msg.received), None)
            if first_hop:
                domain = first_hop.get("by", None)
                domain = next(iter(domain.split()), None)
                sender_ip = next(
                    iter(parse_ipv4_addresses(first_hop.get("from", []))), None
                )
                # sender_ip = self.msg.get_server_ipaddress(domain)

                if domain:
                    # CHECK DMARK
                    try:
                        dmark_result = results_to_json(check_domains(domain))
                        dmark_info = (
                            dmark_result if dmark_result not in [[], "[]"] else None
                        )
                    except Exception as e:
                        logging.error("DMARK ERROR {}".format(e))
                        pass

                    # IF FROM IS INTERNAL ADD FLAG
                    if self.info.internal_domains and any(
                        [
                            domain.find(internal) != -1
                            for internal in self.info.internal_domains
                        ]
                    ):
                        flags.append("Internal")

                if domain and sender_ip:
                    # SPF CHECK
                    sender = self.msg.from_[0][1]
                    try:
                        result, explanation = spf.check2(
                            s=sender, i=sender_ip, h=domain
                        )
                        if result != 250:
                            flags.append("SPF")
                            spf_info = "Sender {0} rejected on {1} ({2}): {3}. Considered Hop: {4}".format(
                                sender,
                                domain,
                                sender_ip,
                                explanation,
                                first_hop,
                            )
                    except Exception as e:
                        logging.error("SPF ERROR [{}] {}".format(sender_ip, e))

                    # MAP COORDS
                    try:
                        info = DbIpCity.get(sender_ip, api_key="free").to_json()
                        geo_info_json = json.loads(info)
                        geo_info = {
                            "type": "Point",
                            "coordinates": [
                                geo_info_json["longitude"],
                                geo_info_json["latitude"],
                            ],
                        }
                    except Exception as e:
                        logging.error("Error geoip {}".format(e))
                        logging.error(e)
                        pass

            # DATE from mail, if error now()
            if not self.msg.date:
                date = timezone.now()
            else:
                date = parse(
                    "{} {}".format(self.msg.date, self.msg.timezone.replace(".", ":"))
                )

            self.db_mail = Mail.objects.create(
                parent=None
                if not self.parent_id
                else Mail.objects.get(pk=self.parent_id),
                message_id=self.msg.message_id,
                subject=self.msg.subject,
                date=date,
                submission_date=timezone.now(),
                received=self.msg.received,
                headers=self.msg.headers,
                text_plain=self.msg.text_plain,
                text_html=self.msg.text_html,
                text_not_managed=self.msg.text_not_managed,
                sender_ip_address=sender_ip,
                to_domains=self.msg.to_domains,
                eml_path=self.mail_filepath,
            )
            self.id = self.db_mail.pk

            self.db_mail.geom = geo_info
            self.db_mail.save()
            self.db_mail.dmark = dmark_info
            self.db_mail.save()
            self.db_mail.dkim = dkim_info
            self.db_mail.save()
            self.db_mail.arc = arc_info
            self.db_mail.save()
            self.db_mail.spf = spf_info
            self.db_mail.save()

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

        # IF MAIL RETURN IT TO BE PROCESSED AGAIN
        if mess_att["mail_content_type"] in [
            "application/ms-tnef",
            "Transport Neutral Encapsulation Format",
        ]:
            self.clean_files((filepath, old_filepath))
            logging.warning("TNEF not supported")
            return False

        elif (
            mess_att["mail_content_type"] == "application/octet-stream"
            and fileext in (".eml", ".msg")
        ) or mess_att["mail_content_type"] == "message/rfc822":
            logging.warning("Attached email!")
            self.childs.append((filepath, fileext))

        # IF TEXT EXTRACT IOC
        elif mess_att["mail_content_type"] in (
            "text/plain",
            "text/html",
        ):
            self.find_ioc(mess_att["payload"])
            self.clean_files((filepath, old_filepath))

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
