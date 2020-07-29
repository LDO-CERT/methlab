from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.template.defaultfilters import truncatechars

# CUSTOM FIELDS
from djgeojson.fields import PointField
from colorfield.fields import ColorField
from django.contrib.postgres.fields import JSONField, ArrayField
from django_better_admin_arrayfield.models.fields import ArrayField  # noqa

# MANAGER
from taggit.managers import TaggableManager

# POSTGRES SWEETERS
import django.contrib.postgres.search as pg_search
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.aggregates import StringAgg
from django.contrib.postgres.search import (
    SearchQuery,
    SearchRank,
    SearchVector,
    TrigramSimilarity,
)


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
    onpremise = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Report(models.Model):

    LEVEL = (
        (0, "none"),
        (1, "info"),
        (2, "safe"),
        (3, "suspicious"),
        (4, "malicious"),
    )

    response = JSONField(blank=True, null=True)
    analyzer = models.ForeignKey(
        Analyzer, on_delete=models.CASCADE, blank=True, null=True
    )
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")
    taxonomies = ArrayField(models.CharField(max_length=50), blank=True, null=True)
    success = models.BooleanField(default=False)


class Address(models.Model):
    name = ArrayField(models.CharField(max_length=500), blank=True, null=True)
    address = models.EmailField(unique=True)
    domain = models.CharField(max_length=500)
    mx_check = models.TextField(blank=True, null=True)

    reports = GenericRelation(Report, related_name="addresses")

    class Meta:
        verbose_name_plural = "addresses"

    def __str__(self):
        return self.address if self.address else ""


class Attachment(models.Model):
    binary = models.BooleanField()
    charset = models.CharField(max_length=500, blank=True, null=True)
    content_transfer_encoding = models.CharField(max_length=500, blank=True, null=True)
    content_disposition = models.TextField(blank=True, null=True)
    content_id = models.CharField(max_length=500, blank=True, null=True)
    filename = ArrayField(models.CharField(max_length=500), blank=True, null=True)
    filepath = models.CharField(max_length=500, blank=True, null=True)
    mail_content_type = models.CharField(max_length=500, blank=True, null=True)
    md5 = models.CharField(max_length=32, blank=True, null=True, unique=True)
    sha1 = models.CharField(max_length=40, blank=True, null=True, unique=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True, unique=True)

    reports = GenericRelation(Report, related_name="attachments")

    def __str__(self):
        return (
            "{} {}".format(self.filename, self.md5)
            if self.filename
            else "{}".format(self.md5)
        )


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
    whois = JSONField(blank=True, null=True)

    reports = GenericRelation(Report, related_name="iocs")

    def __str__(self):
        return self.ip if self.ip else self.domain


class MailManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().exclude(tags__name__in=["SecInc"])

    def search(self, search_text):
        # Multiple language will be available in 3.1
        search_vectors = SearchVector(
            "body", weigth="A", config="english"
        ) + SearchVector("subject", weigth="B", config="english")
        search_query = SearchQuery(search_text)
        search_rank = SearchRank(search_vectors, search_query)
        body_tr_sim = TrigramSimilarity("body", search_text)
        subject_tr_si = TrigramSimilarity("subject", search_text)
        qs = (
            self.get_queryset()
            .filter(search_vector=search_query)
            .annotate(rank=search_rank, similarity=body_tr_sim + subject_tr_si)
            .order_by("-rank")
        )
        return qs


class Mail(models.Model):
    assignee = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    parent = models.ForeignKey("self", blank=True, null=True, on_delete=models.CASCADE)
    message_id = models.CharField(max_length=1000)
    subject = models.CharField(max_length=500)
    date = models.DateTimeField(blank=True, null=True)
    addresses = models.ManyToManyField(
        Address, related_name="addresses", through="Mail_Addresses"
    )
    received = JSONField(blank=True, null=True)
    headers = JSONField(blank=True, null=True)
    geom = PointField(blank=True, null=True)
    body = models.TextField(blank=True, null=True)
    sender_ip_address = models.CharField(max_length=50, blank=True, null=True)
    to_domains = ArrayField(models.CharField(max_length=500), blank=True, null=True)
    iocs = models.ManyToManyField(Ioc, related_name="iocs")
    attachments = models.ManyToManyField(Attachment, related_name="attachments")
    flags = models.ManyToManyField(Flag, related_name="flags", through="Mail_Flag")
    eml_path = models.CharField(max_length=500, blank=True, null=True)
    attachments_path = models.CharField(max_length=500, blank=True, null=True)
    tags = TaggableManager()

    reports = GenericRelation(Report, related_name="mails")

    search_vector = pg_search.SearchVectorField(null=True)

    objects = models.Manager()
    external_objects = MailManager()

    def save(self, *args, **kwargs):
        self.search_vector = SearchVector(
            "body", weigth="A", config="english"
        ) + SearchVector("subject", weigth="B", config="english")
        super().save(*args, **kwargs)

    class Meta:
        indexes = [GinIndex(fields=["search_vector"])]

    @property
    def sender(self):
        return [x for x in self.mail_addresses_set.all() if x.field == "from"][0]

    @property
    def short_id(self):
        return truncatechars(self.message_id, 15)

    @property
    def short_subject(self):
        return truncatechars(self.subject, 80)

    @property
    def tag_list(self):
        return u", ".join(x.name for x in self.tags.all())

    @property
    def flag_list(self):
        return u", ".join([x.name for x in self.flags.all()])

    @property
    def count_attachments(self):
        return self.attachments.count()

    @property
    def count_iocs(self):
        return self.iocs.count()

    def __str__(self):
        return truncatechars(self.subject, 80) if self.subject else ""


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

    def __str__(self):
        return "{}".format(self.address.address)


class Mail_Flag(models.Model):
    mail = models.ForeignKey(Mail, on_delete=models.CASCADE)
    flag = models.ForeignKey(Flag, on_delete=models.CASCADE)
    note = models.TextField(blank=True, null=True)
