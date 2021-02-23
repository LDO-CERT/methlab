import django_tables2 as tables
from django.utils.html import format_html_join, format_html

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
    official_response = tables.Column(orderable=False, verbose_name="Response")
    assignee = tables.Column(orderable=False)
    short_subject = tables.Column(orderable=False, verbose_name="Subject")
    count_attachments = tables.Column(orderable=False, verbose_name="Attachments")
    count_iocs = tables.Column(orderable=False, verbose_name="Iocs")
    tags = tables.Column(orderable=False)
    progress = tables.Column(orderable=False, verbose_name="Status")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = (
            "progress",
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

    def render_progress(self, value, record):
        if value != "done":
            html = format_html("""<span class='badge bg-danger'>{}</span>""", value)
        else:
            html = format_html("""<span class='badge bg-success'>{}</span>""", value)
        return html

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
    tags = tables.Column(orderable=False)

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("attachments__md5", "attachments__sha256", "total", "tags", "link")

    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html


class IpTable(tables.Table):
    link = tables.LinkColumn(
        "search",
        text=">>>",
        args=["ip", A("ips__ip")],
        orderable=False,
    )
    total = tables.Column(verbose_name="Total")
    ips__ip = tables.Column(verbose_name="Ip")
    ips__tags = tables.Column(orderable=False, verbose_name="Tags")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("ips__ip", "total", "ips__tags", "link")

    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html


class UrlTable(tables.Table):
    link = tables.LinkColumn(
        "search",
        text=">>>",
        args=["domain", A("urls__domain__domain")],
        orderable=False,
    )
    total = tables.Column(verbose_name="Total")
    urls__url = tables.Column(verbose_name="Url")
    urls__tags = tables.Column(orderable=False, verbose_name="Tags")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("urls__url", "total", "urls__tags", "link")

    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html


class DomainTable(tables.Table):
    link = tables.LinkColumn(
        "search",
        text=">>>",
        args=["domain", A("urls__domain__domain")],
        orderable=False,
    )
    total = tables.Column(verbose_name="Total")
    urls__domain__domain = tables.Column(verbose_name="Domain")
    urls__domain__tags = tables.Column(orderable=False, verbose_name="Tags")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("urls__domain__domain", "total", "urls__domain__tags", "link")

    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html


class AddressTable(tables.Table):
    link = tables.LinkColumn(
        "search",
        text=">>>",
        args=["mail", A("mail_addresses__address__address")],
        orderable=False,
    )
    tags = tables.Column(orderable=False)
    total = tables.Column(verbose_name="Total")

    class Meta:
        model = Address
        template_name = "django_tables2/bootstrap4.html"
        fields = ("mail_addresses__address__address", "total", "tags", "link")

    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html
