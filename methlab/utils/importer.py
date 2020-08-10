import os
import json
import shutil
import pathlib
import time
import uuid
import spf
import datetime
import mailparser
import magic
import hashlib
import whois
import dns.resolver

from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder
from django.contrib.contenttypes.models import ContentType

from ipwhois import IPWhois
from zipfile import ZipFile, is_zipfile
from dateutil.parser import parse
from tldextract import extract
from checkdmarc import check_domains, results_to_json

# from pymisp import MISPEvent

from glom import glom, PathAccessError
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
    Analyzer,
    Report,
    Whitelist,
)


def default(o):
    """ helpers to store item in json

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
    def __init__(self, msg, info, cortex_api, misp_api, mail_filepath, parent_id=None):
        """
            MethMail main mail class
            arguments:
            - msg: mail object
            - info: info regarding whitelist and vip
            - cortex_api: object to connect to cortex
            - misp_api: object to connect to misp
            - mail_filepath: phisycal path of the mail
            - parent_id: parent id of the mail if processed mail was an attachment
        """
        self.msg = msg
        self.info = info
        self.cortex_api = cortex_api
        self.misp_api = misp_api
        self.mail_filepath = mail_filepath
        self.parent_id = parent_id
        self.db_mail = None  # mail object in db

    def process_mail(self):
        """ Main workflow for single mail.
        """

        # IF MAIL WAS ALREADY PROCESSED IGNORE
        try:
            old_mail = Mail.objects.get(
                message_id=self.msg.message_id, parent_id__pk=self.parent_id
            )
            self.clean_files((self.mail_filepath))
            del old_mail
            return
        except Mail.DoesNotExist:
            pass

        # CREATE OBJECT IN DB
        self.store_info()

        # RUN ANALYZERS ON FULL EMAIL
        self.check_cortex(self.mail_filepath, "file", self.db_mail, is_mail=True)

        # Save attachments
        random_path = self.store_attachments()
        self.db_mail.attachments_path = random_path
        self.db_mail.save()

        # PROCESS ATTACHMENTS
        for mess_att in self.msg.attachments:
            filepath = "{}/{}".format(random_path, mess_att["filename"])

            # I don't have payload or I don't understand type skip
            if not mess_att["mail_content_type"] or not mess_att["payload"]:
                self.clean_files((self.db_mail.eml_path, self.db_mail.attachments_path))
                continue

            self.process_attachment(filepath, mess_att)

        # DELETE MAIL TEMP FILE, here should be safe
        self.clean_files((self.db_mail.eml_path, self.db_mail.attachments_path))

    def check_cortex(self, ioc, ioc_type, object_id, is_mail=False):
        """ Run all available analyzer for ioc.

            arguments:
            - ioc: value/path of item we need to check on cortex
            - ioc_type: type of the ioc (generic_relation and cortex datatype)
            - object_id: item to attach report to
            - is_mail: ioc is a mail [mail datatype is for addresses and file is for mail]
        """

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
        else:
            return False

        old_reports = Report.objects.filter(
            content_type=ContentType.objects.get_for_model(content_type),
            object_id=object_id.pk,
            success=True,
            date__gte=datetime.datetime.today() - datetime.timedelta(days=30),
        )

        for analyzer in analyzers:

            # Check if item was already been processed
            for report in old_reports:
                if report.analyzer == analyzer:
                    if "malicious" in report.taxonomies:
                        self.db_mail.tags.add(
                            "{}: malicious".format(analyzer.name),
                            tag_kwargs={"color": "#FF0000"},
                        )

                    elif "suspicious" in report.taxonomies:
                        self.db_mail.tags.add(
                            "{}: suspicious".format(analyzer.name),
                            tag_kwargs={"color": "#C15808"},
                        )

                    elif "safe" in report.taxonomies:
                        self.db_mail.tags.add(
                            "{}: safe".format(analyzer.name),
                            tag_kwargs={"color": "#00FF00"},
                        )

                    continue

            # If not rerun the analyzer
            try:
                job = self.cortex_api.analyzers.run_by_name(
                    analyzer.name,
                    {"data": ioc, "dataType": ioc_type, "tlp": 1},
                    force=1,
                )
                while job.status not in ["Success", "Failure"]:
                    time.sleep(10)
                    job = self.cortex_api.jobs.get_report(job.id)

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

                    if "malicious" in taxonomies:
                        self.db_mail.tags.add(
                            "{}: malicious".format(analyzer.name),
                            tag_kwargs={"color": "#FF0000"},
                        )

                    elif "suspicious" in taxonomies:
                        self.db_mail.tags.add(
                            "{}: suspicious".format(analyzer.name),
                            tag_kwargs={"color": "#C15808"},
                        )

                    elif "safe" in taxonomies:
                        self.db_mail.tags.add(
                            "{}: safe".format(analyzer.name),
                            tag_kwargs={"color": "#00FF00"},
                        )

                elif job.status == "Failure":
                    report = Report(
                        content_object=object_id, analyzer=analyzer, success=False,
                    )
                    report.save()

            except Exception as excp:
                print(
                    "ERROR running analyzer {} for {}: {}".format(
                        analyzer.name, ioc, excp
                    )
                )

    def create_misp_event(self):
        """ If mail is not safe store info in misp
        """
        return
        # self.misp_api
        # event = MISPEvent()
        # event.info("[METH]")
        # event.distribution = 0
        # event.threat_level_id = 2
        # event.analysis = 1
        # event.add_tag("tlp:white")
        # event.date = self.db_mail.date

    def find_ioc(self, payload):
        """" Extracts url and ip from text.

            arguments:
            - payload: message body
        """
        all_wl = Whitelist.objects.all()

        # EXTRACT URL, CHECK IF WL AND GET REPORT
        for url in parse_urls(payload):
            whois_info = None
            url = url.split(">")[0].rstrip('"].').strip("/").lower()
            domain = ".".join(part for part in extract(url) if part)
            if domain in [x.value for x in all_wl if x.type == "domain"]:
                continue

            ioc, created = Ioc.objects.get_or_create(domain=domain,)
            if created:
                try:
                    whois_info = json.loads(
                        json.dumps(
                            whois.query(domain).__dict__,
                            cls=DjangoJSONEncoder,
                            default=default,
                        )
                    )
                except Exception as e:
                    print(e)

            if ioc.urls and url not in ioc.urls:
                ioc.urls.append(url)
            elif not ioc.urls:
                ioc.urls = [url]
            ioc.whois = whois_info
            ioc.save()
            self.db_mail.iocs.add(ioc)
            self.check_cortex(url, "url", ioc)

        # EXTRACT IP, CHECK IF WL AND GET REPORT
        for ip in (
            parse_ipv4_addresses(payload)
            + parse_ipv4_cidrs(payload)
            + parse_ipv6_addresses(payload)
        ):
            whois_info = None
            if ip in [x.value for x in all_wl if x.type == "ip"]:
                continue

            ioc, created = Ioc.objects.get_or_create(ip=ip)
            if created:
                try:
                    whois_info = IPWhois(ip).lookup_rdap(depth=1)
                except Exception:
                    pass
            ioc.whois = whois_info
            ioc.save()
            self.db_mail.iocs.add(ioc)
            self.check_cortex(ip, "ip", ioc)

    def store_info(self):
        """ Clean mail fields and create item in db
        """
        flags = []
        addresses_list = []

        mail_wl = Whitelist.objects.filter(type="address")

        geo_info = None
        dmark_info = None

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
                return

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
                flags.append(
                    (
                        "Fake Real Name",
                        "Mail name contains mail different from mail address",
                    )
                )
            if self.info.vip_list:
                for vip in self.info.vip_list:
                    if (
                        name.find(vip) != -1
                        and address_from.find(self.info.vip_domain) == -1
                    ):
                        flags.append(("VIP SCAM", "{} mail for {}".format(name, vip),))

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
                except Exception as e:
                    print(e)

                try:
                    dmark_info = results_to_json(check_domains(domain))
                except Exception as e:
                    print(e)

                # SPF CHECK
                domain = domain.split()[0]
                sender = self.msg.from_[0][1]
                spf_check = spf.check(s=sender, i=ip, h=domain)
                if spf_check[1] != 250:
                    flags.append(
                        (
                            "SPF",
                            "Sender {0} rejected on {1} ({2}): {3}. Considered Hop: {4}".format(
                                sender, domain, ip, spf_check[2], first_hop,
                            ),
                        )
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
                flags.append(("Internal", ""))

        # DATE from mail, if error now()
        if not self.msg.date:
            date = timezone.now()
        else:
            date = parse(
                "{} {}".format(self.msg.date, self.msg.timezone.replace(".", ":"))
            )

        self.db_mail = Mail(
            parent=None if not self.parent_id else Mail(self.parent_id),
            message_id=self.msg.message_id,
            subject=self.msg.subject,
            date=date,
            submission_date=date if not self.parent_id else Mail(self.parent_id).date,
            received=self.msg.received,
            headers=self.msg.headers,
            body=self.msg.body,
            sender_ip_address=self.msg.get_server_ipaddress(self.info.imap_server),
            to_domains=self.msg.to_domains,
            geom=geo_info,
            dmark=dmark_info,
            # this is an .eml if parent is None otherwhise is the parent attachment folder
            eml_path=self.mail_filepath,
        )
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
                    [addr_item.address.endswith(x) for x in self.info.honeypot_emails]
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
                self.check_cortex(addr_item.address, "mail", addr_item, is_mail=False)

        if self.db_mail.tags.count() == 0:
            self.db_mail.tags.add("Hunting")

        self.find_ioc(self.db_mail.body)

        # STORE FLAGS IN DB
        for flag, note in flags:
            self.db_mail.tags.add(flag)  # , tag_kwargs={"note": note})

    def store_attachments(self):
        """ Store attachment to disk.

            returns:
            - random_path: path on disk containing attachments
        """
        random_path = "/tmp/{}".format(uuid.uuid4())
        os.makedirs(random_path)
        self.msg.write_attachments(random_path)
        return random_path

    def clean_files(self, filepaths):
        """ Clean a file or folder.

            arguments:
            - filepath: path to delete
        """
        try:
            for filepath in filepaths:
                if os.path.isdir(filepath):
                    shutil.rmtree(filepath)
                elif os.path.isfile(filepath):
                    os.remove(filepath)
        except Exception as e:
            print(e)

    def is_whitelisted(self, content_type, mimetype_whitelist=None):
        """" Checks if content_type is whitelisted.

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
        return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()

    def process_attachment(self, filepath, mess_att):
        """ Check if attachments is whitelisted, zipped, another mail or text:

            arguments:
            - filepath: path of the attachment
            - mess_att: attachment obcject
        """

        all_wl = Whitelist.objects.all()
        _, fileext = os.path.splitext(mess_att["filename"])
        fileext = fileext.lower()

        if not os.path.exists(filepath):
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
                    self.clean_files(
                        (self.db_mail.eml_path, self.db_mail.attachments_path)
                    )
                    return False

        if self.is_whitelisted(
            mess_att["mail_content_type"], self.info.mimetype_whitelist
        ):
            self.clean_files((self.db_mail.eml_path, self.db_mail.attachments_path))
            return False

        # IF MAIL PROCESS RECURSIVELY
        if mess_att["mail_content_type"] in [
            "application/ms-tnef",
            "Transport Neutral Encapsulation Format",
        ]:
            print("TNEF -- see old release for support")
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
                misp_api=self.misp_api,
                mail_filepath=filepath,
            )
            internal_methmail.process_mail()

        # IF TEXT EXTRACT IOC
        elif mess_att["mail_content_type"] in ("text/plain", "text/html",):
            self.find_ioc(mess_att["payload"])

        # IF GENERIC FILE, EXTRACT MD5/SHA256 AND GET REPORT
        else:
            md5, sha1, sha256 = self.get_hashes(filepath)
            if md5 in [x.value for x in all_wl if x.type == "md5"] or sha256 in [
                x.value for x in all_wl if x.type == "sha256"
            ]:
                self.clean_files((self.db_mail.eml_path, self.db_mail.attachments_path))
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
            self.db_mail.attachments.add(attachment)
            # Check file in onprems sandboxes
            self.check_cortex(filepath, "file", attachment)
            # Check hashes in cloud services
            self.check_cortex(attachment.sha256, "hash", attachment)
