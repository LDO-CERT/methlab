from django.db import models
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db.models.fields.related import ForeignKey
from django.template.defaultfilters import truncatechars
from django.utils.translation import ugettext_lazy as _
from django.utils.text import slugify

# CUSTOM FIELDS
from djgeojson.fields import PointField
from colorfield.fields import ColorField
from django_better_admin_arrayfield.models.fields import ArrayField

# TAGS
from taggit.managers import TaggableManager
from taggit.models import TagBase, GenericTaggedItemBase

# POSTGRES SWEETERS
import django.contrib.postgres.search as pg_search
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import (
    SearchQuery,
    SearchRank,
    SearchVector,
    TrigramSimilarity,
)

RESPONSE = (
    (0, "Unknown"),
    (1, "SPAM"),
    (2, "HAM"),
    (3, "Phishing"),
    (4, "Social Engineering"),
    (5, "Reconnaissance"),
    (6, "BlackMail"),
    (7, "CEO SCAM"),
    (10, "Safe"),
)

TAXONOMIES = (
    (0, "none"),
    (1, "info"),
    (2, "safe"),
    (3, "suspicious"),
    (4, "malicious"),
)


class InternalInfo(models.Model):
    name = models.CharField(max_length=200)
    imap_server = models.CharField(max_length=200)
    imap_username = models.CharField(max_length=200)
    imap_password = models.CharField(max_length=200)
    imap_folder = models.CharField(max_length=200)

    cortex_url = models.CharField(max_length=200)
    cortex_api = models.CharField(max_length=200)

    misp_url = models.CharField(max_length=200, blank=True, null=True)
    misp_api = models.CharField(max_length=200, blank=True, null=True)

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

    cortex_expiration_days = models.IntegerField(default=30)
    whois_expiration_days = models.IntegerField(default=30)

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
    response = models.JSONField(blank=True, null=True)
    analyzer = models.ForeignKey(
        Analyzer, on_delete=models.CASCADE, blank=True, null=True
    )
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")
    taxonomies = ArrayField(models.CharField(max_length=50), blank=True, null=True)
    success = models.BooleanField(default=False)
    date = models.DateField(auto_now_add=True)


class Whois(models.Model):
    response = models.JSONField(blank=True, null=True)
    date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.response


class Whitelist(models.Model):
    WL_TYPE = (
        ("address", "address"),
        ("domain", "domain"),
        ("url", "url"),
        ("ip", "ip"),
        ("md5", "md5"),
        ("sha256", "sha256"),
    )
    value = models.CharField(max_length=1000)
    type = models.CharField(max_length=8, choices=WL_TYPE)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["value", "type"], name="duplicated_wl")
        ]

    def __str__(self):
        return "[{}] {}".format(self.type, self.value)


class Flag(TagBase):
    color = ColorField(default="#30357B")
    visible = models.BooleanField(default=True)

    class Meta:
        verbose_name = _("Tag")
        verbose_name_plural = _("Tags")

    def __str__(self):
        return self.name


class CustomTag(GenericTaggedItemBase):
    tag = models.ForeignKey(
        Flag, related_name="%(app_label)s_%(class)ss", on_delete=models.CASCADE
    )


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
    tags = TaggableManager(through=CustomTag, blank=True)
    whitelisted = models.BooleanField(default=False)
    taxonomy = models.IntegerField(default=0, choices=TAXONOMIES)

    def __str__(self):
        return (
            "{} {}".format(self.filename, self.md5)
            if self.filename
            else "{}".format(self.md5)
        )


class Address(models.Model):
    name = ArrayField(models.CharField(max_length=500), blank=True, null=True)
    address = models.EmailField(unique=True)
    domain = models.CharField(max_length=500)
    mx_check = models.TextField(blank=True, null=True)
    reports = GenericRelation(Report, related_name="addresses")
    tags = TaggableManager(through=CustomTag, blank=True)
    taxonomy = models.IntegerField(default=0, choices=TAXONOMIES)

    class Meta:
        verbose_name_plural = "addresses"

    def __str__(self):
        return self.address if self.address else ""


class Domain(models.Model):
    domain = models.CharField(max_length=200)
    dig = models.TextField(blank=True, null=True)
    whois = ForeignKey(
        Whois, related_name="domain", on_delete=models.CASCADE, null=True, blank=True
    )
    reports = GenericRelation(Report, related_name="domains")
    tags = TaggableManager(through=CustomTag, blank=True)
    whitelisted = models.BooleanField(default=False)
    taxonomy = models.IntegerField(default=0, choices=TAXONOMIES)

    def __str__(self):
        return self.domain


class Ip(models.Model):
    ip = models.GenericIPAddressField()
    whois = ForeignKey(
        Whois, related_name="ip", on_delete=models.CASCADE, null=True, blank=True
    )
    reports = GenericRelation(Report, related_name="ips")
    tags = TaggableManager(through=CustomTag, blank=True)
    whitelisted = models.BooleanField(default=False)
    taxonomy = models.IntegerField(default=0, choices=TAXONOMIES)

    def __str__(self):
        return "{}".format(self.ip)


class Url(models.Model):
    url = models.CharField(max_length=2000)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    reports = GenericRelation(Report, related_name="urls")
    tags = TaggableManager(through=CustomTag, blank=True)
    whitelisted = models.BooleanField(default=False)
    taxonomy = models.IntegerField(default=0, choices=TAXONOMIES)

    def __str__(self):
        return self.url


class MailManager(models.Manager):
    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .exclude(tags__name__in=["SecInc"])
            .exclude(subject__isnull=True)
            .exclude(subject="")
        )

    def search(self, search_text):
        search_vectors = (
            SearchVector("text_plain", weight="A", config="english")
            + SearchVector("text_html", weight="A", config="english")
            + SearchVector("subject", weight="B", config="english")
        )
        search_query = SearchQuery(search_text)
        search_rank = SearchRank(search_vectors, search_query)
        subject_tr_si = TrigramSimilarity("subject", search_text)
        qs = (
            self.get_queryset()
            .filter(search_vector=search_query)
            .annotate(
                rank=search_rank,
                similarity=subject_tr_si,
            )
            .order_by("-rank")
        )
        return qs


class Mail(models.Model):

    PROGRESS = (
        (0, "new"),
        (1, "processing"),
        (2, "done"),
    )

    # WORKFLOW
    progress = models.PositiveIntegerField(choices=PROGRESS, default=0)
    official_response = models.PositiveIntegerField(choices=RESPONSE, default=0)
    assignee = models.ForeignKey(
        get_user_model(), on_delete=models.CASCADE, null=True, blank=True
    )

    # SUBMISSION INFO
    parent = models.ForeignKey("self", blank=True, null=True, on_delete=models.CASCADE)

    # to sort by submission_date :)
    submission_date = models.DateTimeField(blank=True, null=True)

    # MAIL INFO
    message_id = models.CharField(max_length=1000)
    subject = models.CharField(max_length=1000)
    slug_subject = models.SlugField(max_length=1000, editable=False, default="")
    date = models.DateTimeField(blank=True, null=True)
    addresses = models.ManyToManyField(
        Address, related_name="addresses", through="Mail_Addresses"
    )
    received = models.JSONField(blank=True, null=True)
    headers = models.JSONField(blank=True, null=True)
    text_plain = ArrayField(
        models.TextField(blank=True, null=True), blank=True, null=True
    )
    text_html = ArrayField(
        models.TextField(blank=True, null=True), blank=True, null=True
    )
    text_not_managed = ArrayField(
        models.TextField(blank=True, null=True), blank=True, null=True
    )
    sender_ip_address = models.CharField(max_length=50, blank=True, null=True)
    to_domains = ArrayField(models.CharField(max_length=500), blank=True, null=True)

    # ADDITIONAL FIELDS
    geom = PointField(blank=True, null=True)

    dmark = models.TextField(blank=True, null=True)
    dkim = models.TextField(blank=True, null=True)
    spf = models.TextField(blank=True, null=True)
    arc = models.JSONField(blank=True, null=True)

    # IOC
    ips = models.ManyToManyField(Ip, related_name="ips")
    urls = models.ManyToManyField(Url, related_name="urls")
    attachments = models.ManyToManyField(Attachment, related_name="attachments")

    # TAGS
    tags = TaggableManager(through=CustomTag, blank=True)

    # STORAGE INFO
    eml_path = models.CharField(max_length=500, blank=True, null=True)
    attachments_path = models.CharField(max_length=500, blank=True, null=True)

    # ATTACHED REPORT
    reports = GenericRelation(Report, related_name="mails")
    taxonomy = models.IntegerField(default=0, choices=TAXONOMIES)

    # SEARCH FIELD
    search_vector = pg_search.SearchVectorField(null=True)

    objects = models.Manager()
    external_objects = MailManager()

    # Update search vectors works only in update
    def save(self, *args, **kwargs):
        if self._state.adding is False:
            self.search_vector = (
                SearchVector("text_plain", weight="A", config="english")
                + SearchVector("text_html", weight="A", config="english")
                + SearchVector("subject", weight="B", config="english")
            )
        self.slug_subject = slugify(self.subject, allow_unicode=True)
        super().save(*args, **kwargs)

    class Meta:
        indexes = [GinIndex(fields=["search_vector"])]

    @property
    def sender(self):
        sender = next(iter(self.mail_addresses_set.from_addresses()), None)
        if sender:
            flags = Flag.objects.all()
            suspicious_tags = [x for x in flags if x.name.find("suspicious") != -1]
            malicious_tags = [x for x in flags if x.name.find("malicious") != -1]
            return [
                sender.address.tags.filter(name__in=suspicious_tags).count(),
                sender.address.tags.filter(name__in=malicious_tags).count(),
                sender.address,
            ]
        return None

    @property
    def receivers(self):
        try:
            info = InternalInfo.objects.first()
        except:
            info = None
        recvs = [
            x.address.address
            for x in self.mail_addresses_set.all()
            if x.field in ["to", "cc", "bcc"]
        ]
        cleaned_recvs = []
        if info and info.internal_domains:
            for x in recvs:
                if "@{}".format(x.split("@")[1]) in info.internal_domains:
                    cleaned_recvs.append(x.split("@")[0])
                else:
                    cleaned_recvs.append(x)
        else:
            cleaned_recvs = recvs
        return [", ".join(recvs), ", ".join(cleaned_recvs)]

    @property
    def tos(self):
        return self.mail_addresses_set.to_addresses()

    @property
    def ccs(self):
        return self.mail_addresses_set.cc_addresses()

    @property
    def bccs(self):
        return self.mail_addresses_set.bcc_addresses()

    @property
    def reply(self):
        return self.mail_addresses_set.reply_to_addresses()

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
    def count_iocs(self):
        return self.ips.count() + self.urls.count() + self.attachments.count()

    @property
    def render_iocs(self):

        ips = self.ips.all()
        ips_level = max([ip.taxonomy for ip in ips] + [0])

        urls = self.urls.all()
        urls_level = max([url.taxonomy for url in urls] + [0])

        attachments = self.attachments.all()
        attachments_level = max(
            [attachment.taxonomy for attachment in attachments] + [0]
        )

        ioc_class = {
            0: "bg-light text-dark",
            1: "bg-light text-dark",
            2: "bg-success",
            3: "bg-warning text-dark",
            4: "bg-danger",
        }

        return [
            ioc_class[ips_level],
            ips.count(),
            ioc_class[urls_level],
            urls.count(),
            ioc_class[attachments_level],
            attachments.count(),
        ]

    def __str__(self):
        return truncatechars(self.subject, 80) if self.subject else ""


class AddressQueryset(models.QuerySet):
    def from_addresses(self):
        return self.filter(field="from")

    def to_addresses(self):
        return self.filter(field="to")

    def bcc_addresses(self):
        return self.filter(field="bcc")

    def cc_addresses(self):
        return self.filter(field="cc")

    def reply_to_addresses(self):
        return self.filter(field="reply_to")


class AddressManager(models.Manager):
    def get_queryset(self):
        return AddressQueryset(self.model, using=self._db)

    def from_addresses(self):
        return self.get_queryset().from_addresses()

    def to_addresses(self):
        return self.get_queryset().to_addresses()

    def bcc_addresses(self):
        return self.get_queryset().bcc_addresses()

    def cc_addresses(self):
        return self.get_queryset().cc_addresses()

    def reply_to_addresses(self):
        return self.get_queryset().reply_to_addresses()


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
    objects = AddressManager()

    def __str__(self):
        return "{}".format(self.address.address)
