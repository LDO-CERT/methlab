import django_tables2 as tables
from django.utils.html import format_html_join

from django_tables2.utils import A
from methlab.shop.models import Mail, Address


class MailTable(tables.Table):
    link = tables.LinkColumn(
        "search", text=">>>", args=["subject", A("slug_subject")], orderable=False
    )
    subject = tables.Column(verbose_name="Subject")
    total = tables.Column(verbose_name="Total")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("subject", "total", "link")


class LatestMailTable(tables.Table):
    link = tables.LinkColumn("mail_detail", text=">>>", args=[A("pk")], orderable=False)
    similar = tables.LinkColumn(
        "search", text="🔎", args=["subject", A("slug_subject")], orderable=False
    )
    submission_date = tables.DateTimeColumn(orderable=False, format="M d Y, h:i A")
    official_response = tables.Column(orderable=False)
    assignee = tables.Column(orderable=False)
    short_subject = tables.Column(orderable=False)
    count_attachments = tables.Column(orderable=False)
    count_iocs = tables.Column(orderable=False)
    tags = tables.Column(orderable=False)

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = (
            "submission_date",
            "short_subject",
            "official_response",
            "assignee",
            "tags",
            "count_attachments",
            "count_iocs",
            "link",
            "similar",
        )

    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html


class AttachmentTable(tables.Table):
    link = tables.LinkColumn(
        "search",
        text=">>>",
        args=["attachment", A("attachments__sha256")],
        orderable=False,
    )
    total = tables.Column(verbose_name="Total")
    attachments__md5 = tables.Column(verbose_name="MD5")
    attachments__sha256 = tables.Column(verbose_name="SHA256")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("attachments__md5", "attachments__sha256", "total", "link")


class IocTable(tables.Table):
    link = tables.LinkColumn(
        "search", text=">>>", args=["ioc", A("iocs__domain")], orderable=False,
    )
    total = tables.Column(verbose_name="Total")
    iocs__ip = tables.Column(verbose_name="Ip")
    iocs__domain = tables.Column(verbose_name="Domain")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("iocs__ip", "iocs__domain", "total", "link")


class AddressTable(tables.Table):
    link = tables.LinkColumn(
        "search",
        text=">>>",
        args=["mail", A("mail_addresses__address__address")],
        orderable=False,
    )
    total = tables.Column(verbose_name="Total")

    class Meta:
        model = Address
        template_name = "django_tables2/bootstrap4.html"
        fields = ("mail_addresses__address__address", "total", "link")
