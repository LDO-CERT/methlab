import django_tables2 as tables
from django.utils.html import format_html_join, format_html
from django_tables2.utils import A
from methlab.shop.models import Mail, Address


class MailTable(tables.Table):
    subject = tables.Column(verbose_name="Subject")
    total = tables.Column(verbose_name="Total")
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["subject", A("slug_subject")],
        orderable=False,
    )

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("subject", "total", "search")


class LatestMailTable(tables.Table):
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

    link = tables.LinkColumn(
        "mail_detail",
        text=format_html("<i class='far fa-envelope-open'></i>"),
        args=[A("pk")],
        orderable=False,
    )
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["subject", A("slug_subject")],
        orderable=False,
    )
    submission_date = tables.DateTimeColumn(orderable=False, format="M d Y, h:i A")
    official_response = tables.Column(orderable=False, verbose_name="Response")
    assignee = tables.Column(orderable=False)
    short_subject = tables.Column(orderable=False, verbose_name="Subject")
    count_attachments = tables.Column(orderable=False, verbose_name="Attachments")
    count_iocs = tables.Column(orderable=False, verbose_name="Iocs")
    tags = tables.Column(orderable=False)
    sender = tables.Column(orderable=False)
    receivers = tables.Column(orderable=False)
    progress = tables.Column(orderable=False, verbose_name="Status")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = (
            "progress",
            "submission_date",
            "short_subject",
            "sender",
            "receivers",
            "tags",
            "count_attachments",
            "count_iocs",
            "link",
            "search",
            "official_response",
            "assignee",
        )


class AttachmentTable(tables.Table):
    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html

    total = tables.Column(verbose_name="Total")
    attachments__md5 = tables.Column(verbose_name="MD5")
    attachments__sha256 = tables.Column(verbose_name="SHA256")
    tags = tables.Column(orderable=False)
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["attachment", A("attachments__sha256")],
        orderable=False,
    )

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("attachments__md5", "attachments__sha256", "total", "tags", "search")


class IpTable(tables.Table):
    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html

    total = tables.Column(verbose_name="Total")
    ips__ip = tables.Column(verbose_name="Ip")
    ips__tags = tables.Column(orderable=False, verbose_name="Tags")
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["ip", A("ips__ip")],
        orderable=False,
    )

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("ips__ip", "total", "ips__tags", "search")


class UrlTable(tables.Table):
    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html

    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["domain", A("urls__domain__domain")],
        orderable=False,
    )
    total = tables.Column(verbose_name="Total")
    urls__url = tables.Column(verbose_name="Url")
    urls__tags = tables.Column(orderable=False, verbose_name="Tags")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("urls__url", "total", "urls__tags", "search")


class DomainTable(tables.Table):
    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html

    total = tables.Column(verbose_name="Total")
    urls__domain__domain = tables.Column(verbose_name="Domain")
    urls__domain__tags = tables.Column(orderable=False, verbose_name="Tags")
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["domain", A("urls__domain__domain")],
        orderable=False,
    )

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("urls__domain__domain", "total", "urls__domain__tags", "search")


class AddressTable(tables.Table):
    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html

    tags = tables.Column(orderable=False)
    total = tables.Column(verbose_name="Total")
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["mail", A("mail_addresses__address__address")],
        orderable=False,
    )

    class Meta:
        model = Address
        template_name = "django_tables2/bootstrap4.html"
        fields = ("mail_addresses__address__address", "total", "tags", "search")
