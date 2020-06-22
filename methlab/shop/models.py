from django.db import models
from colorfield.fields import ColorField
from taggit.managers import TaggableManager
from django.contrib.postgres.fields import JSONField, ArrayField
from django_better_admin_arrayfield.models.fields import ArrayField  # noqa


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
    honeypot_emails = ArrayField(models.EmailField(), blank=True, null=True)
    internal_domains = ArrayField(
        models.CharField(max_length=100), blank=True, null=True
    )

    http_proxy = models.CharField(max_length=200, blank=True, null=True)
    https_proxy = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return self.name


class Address(models.Model):
    name = models.CharField(max_length=200, blank=True, null=True)
    address = models.EmailField(blank=True, null=True)
    whitelist = models.BooleanField(default=False)

    def __str__(self):
        return self.address if self.address else ""


class Attachment(models.Model):
    binary = models.BooleanField()
    charset = models.CharField(max_length=200, blank=True, null=True)
    content_transfer_encoding = models.CharField(max_length=200, blank=True, null=True)
    content_disposition = models.TextField(blank=True, null=True)
    content_id = models.CharField(max_length=200, blank=True, null=True)
    filename = models.CharField(max_length=500, blank=True, null=True)
    filepath = models.CharField(max_length=500, blank=True, null=True)
    mail_content_type = models.CharField(max_length=200, blank=True, null=True)
    payload = models.TextField(blank=True, null=True)
    mail = models.ForeignKey("Mail", on_delete=models.CASCADE)


class Flag(models.Model):
    name = models.CharField(max_length=100)
    color = ColorField()
    visible = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Ioc(models.Model):
    ip = models.GenericIPAddressField(blank=True, null=True)
    urls = ArrayField(models.CharField(max_length=500), blank=True, null=True)
    domain = models.CharField(max_length=200)
    whitelisted = models.BooleanField(default=False)

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
    text_plain = models.TextField(blank=True, null=True)
    text_not_managed = models.TextField(blank=True, null=True)
    body = models.TextField(blank=True, null=True)
    body_plain = models.TextField(blank=True, null=True)
    sender_ip_address = models.CharField(max_length=50, blank=True, null=True)
    to_domains = ArrayField(models.CharField(max_length=200), blank=True, null=True)
    iocs = models.ManyToManyField(Ioc, related_name="iocs")
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
