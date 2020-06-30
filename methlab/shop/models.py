from django.db import models
from colorfield.fields import ColorField
from taggit.managers import TaggableManager
from django.contrib.postgres.fields import JSONField, ArrayField
from django_better_admin_arrayfield.models.fields import ArrayField  # noqa
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType


class InternalInfo(models.Model):
    name = models.CharField(max_length=200)
    imap_server = models.CharField(max_length=200)
    imap_username = models.CharField(max_length=200)
    imap_password = models.CharField(max_length=200)
    imap_folder = models.CharField(max_length=200)

    cortex_url = models.CharField(max_length=200)
    cortex_api = models.CharField(max_length=200)

    misp_url = models.CharField(max_length=200)
    misp_api = models.CharField(max_length=200)

    server_list = ArrayField(models.CharField(max_length=100), blank=True, null=True)
    vip_list = ArrayField(models.CharField(max_length=100), blank=True, null=True)
    vip_domain = models.CharField(max_length=200)

    mimetype_whitelist = ArrayField(
        models.CharField(max_length=100), blank=True, null=True
    )

    security_emails = ArrayField(models.EmailField(), blank=True, null=True)
    honeypot_emails = ArrayField(
        models.CharField(max_length=200), blank=True, null=True
    )
    internal_domains = ArrayField(
        models.CharField(max_length=100), blank=True, null=True
    )

    http_proxy = models.CharField(max_length=200, blank=True, null=True)
    https_proxy = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return self.name


class Analyzer(models.Model):
    PRIORITY = (
        (1, "Low"),
        (2, "Medium"),
        (3, "High"),
    )
    name = models.CharField(max_length=200, blank=True, null=True)
    disabled = models.BooleanField(default=False)
    supported_types = ArrayField(models.CharField(max_length=10), blank=True, null=True)
    priority = models.PositiveIntegerField(choices=PRIORITY, default=1)

    def __str__(self):
        return self.name


class Report(models.Model):
    response = JSONField(blank=True, null=True)
    analyzer = models.ForeignKey(
        Analyzer, on_delete=models.CASCADE, blank=True, null=True
    )
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")


class Address(models.Model):
    name = ArrayField(models.CharField(max_length=200), blank=True, null=True)
    address = models.EmailField(blank=True, null=True, unique=True)

    def __str__(self):
        return self.address if self.address else ""


class Attachment(models.Model):
    binary = models.BooleanField()
    charset = models.CharField(max_length=200, blank=True, null=True)
    content_transfer_encoding = models.CharField(max_length=200, blank=True, null=True)
    content_disposition = models.TextField(blank=True, null=True)
    content_id = models.CharField(max_length=200, blank=True, null=True)
    filename = ArrayField(models.CharField(max_length=500), blank=True, null=True)
    filepath = models.CharField(max_length=500, blank=True, null=True)
    mail_content_type = models.CharField(max_length=200, blank=True, null=True)
    md5 = models.CharField(max_length=32, blank=True, null=True, unique=True)
    sha1 = models.CharField(max_length=40, blank=True, null=True, unique=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True, unique=True)


class Flag(models.Model):
    name = models.CharField(max_length=100)
    color = ColorField()
    visible = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Whitelist(models.Model):
    WL_TYPE = (
        ("address", "address"),
        ("domain", "domain"),
        ("ip", "ip"),
        ("md5", "md5"),
        ("sha256", "sha256"),
    )
    value = models.CharField(max_length=500)
    type = models.CharField(max_length=8, choices=WL_TYPE)

    def __str__(self):
        return "[{}] {}".format(self.type, self.value)


class Ioc(models.Model):
    ip = models.GenericIPAddressField(blank=True, null=True)
    urls = ArrayField(models.CharField(max_length=500), blank=True, null=True)
    domain = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return self.ip if self.ip else self.domain


class Mail(models.Model):
    parent = models.ForeignKey("self", blank=True, null=True, on_delete=models.CASCADE)
    message_id = models.CharField(max_length=200)
    subject = models.CharField(max_length=500)
    date = models.DateTimeField(blank=True, null=True)
    addresses = models.ManyToManyField(
        Address, related_name="addresses", through="Mail_Addresses"
    )
    received = JSONField(blank=True, null=True)
    headers = JSONField(blank=True, null=True)
    defects = models.TextField(blank=True, null=True)
    defects_categories = ArrayField(
        models.CharField(max_length=200), blank=True, null=True
    )
    body = models.TextField(blank=True, null=True)
    sender_ip_address = models.CharField(max_length=50, blank=True, null=True)
    to_domains = ArrayField(models.CharField(max_length=200), blank=True, null=True)
    iocs = models.ManyToManyField(Ioc, related_name="iocs")
    attachments = models.ManyToManyField(Attachment, related_name="attachments")
    flags = models.ManyToManyField(Flag, related_name="flags", through="Mail_Flag")
    tags = TaggableManager()

    def __str__(self):
        return self.subject if self.subject else ""


class Mail_Addresses(models.Model):

    FIELDS = (
        ("from", "from"),
        ("to", "to"),
        ("bcc", "bcc"),
        ("cc", "cc"),
        ("reply_to", "reply_to"),
    )

    mail = models.ForeignKey(Mail, on_delete=models.CASCADE)
    address = models.ForeignKey(Address, on_delete=models.CASCADE)
    field = models.CharField(max_length=10, choices=FIELDS)


class Mail_Flag(models.Model):
    mail = models.ForeignKey(Mail, on_delete=models.CASCADE)
    flag = models.ForeignKey(Flag, on_delete=models.CASCADE)
    note = models.TextField(blank=True, null=True)
