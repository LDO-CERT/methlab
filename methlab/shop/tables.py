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
    def render_progress(self, value):
        if value != "done":
            html = format_html("""<span class='badge bg-danger'>{}</span>""", value)
        else:
            html = format_html("""<span class='badge bg-success'>{}</span>""", value)
        return html

    def render_tags(self, value):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html

    def render_sender(self, value, record):
        if not value:
            return format_html(
                """
                <dl class="row">
                    <dt class="col-sm-2"><i class="fas fa-user-edit"></i></dt>
                    <dd class="col-sm-10">{}</dd>
                    <dt class="col-sm-2"><i class="fas fa-user-friends"></i></dt>
                    <dd class="col-sm-10" data-toggle="tooltip" data-html="true" title="{}">{}</dd>
                </dl>
                """,
                value,
                *record.receivers,
            )
        return format_html(
            """
            <dl class="row">
                <dt class="col-sm-2"><i class="fas fa-user-edit"></i></dt>
                <dd class="col-sm-10" data-toggle="tooltip" data-html="true" title="Suspicious: {} - Malicious: {}">{}</dd>
                <dt class="col-sm-2"><i class="fas fa-user-friends"></i></dt>
                <dd class="col-sm-10" data-toggle="tooltip" data-html="true" title="{}">{}</dd>
            </dl>
            """,
            *value,
            *record.receivers,
        )

    def render_submission_date(self, value, record):
        return format_html(
            """
            <dl class="row">
                <dt class="col-sm-2"><i class="far fa-paper-plane"></i></dt>
                <dd class="col-sm-10">{}</dd>
                <dt class="col-sm-2"><i class="fas fa-inbox"></i></dt>
                <dd class="col-sm-10">{}</dd>
            </dl>
            """,
            value.strftime("%Y/%m/%d %H:%M"),
            record.date.strftime("%Y/%m/%d %H:%M"),
        )

    def render_count_iocs(self, value):
        return format_html(
            """
            <dl class="row">
                <dt class="col-sm-4"><i class="fas fa-map-marker-alt"></i></dt>
                <dd class="col-sm-8"><span class="badge badge-{}">{}</span></dd>
                <dt class="col-sm-4"><i class="fas fa-globe"></i></dt>
                <dd class="col-sm-8"><span class="badge badge-{}">{}</span></dd>
                <dt class="col-sm-4"><i class="fas fa-paperclip"></i></dt>
                <dd class="col-sm-8"><span class="badge badge-{}">{}</span></dd>
            </dl>
            """,
            *value,
        )

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
    submission_date = tables.DateTimeColumn(orderable=False, verbose_name="Date")
    official_response = tables.Column(orderable=False, verbose_name="Response")
    assignee = tables.Column(orderable=False)
    sender = tables.Column(orderable=False, verbose_name="From/To")
    short_subject = tables.Column(orderable=False, verbose_name="Subject")
    count_iocs = tables.Column(orderable=False, verbose_name="Iocs")
    tags = tables.Column(orderable=False)
    progress = tables.Column(orderable=False, verbose_name="Status")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        attrs = {"class": "table table-striped table-bordered"}
        fields = (
            "progress",
            "submission_date",
            "short_subject",
            "sender",
            "tags",
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
    tags = tables.Column(orderable=False)
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["ip", A("ips__ip")],
        orderable=False,
    )

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("ips__ip", "total", "tags", "search")


class UrlTable(tables.Table):
    def render_tags(self, value, record):
        html = format_html_join(
            "\n",
            """<span class='badge' style='background-color:{}'>{}</span>""",
            ((x.color, x.name) for x in value.all()),
        )
        return html

    def render_urls__url(self, value, record):
        if len(value) > 50:
            return format_html("<a title='{}'>{} ...</a>".format(value, value[:50]))
        else:
            return value

    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["domain", A("urls__domain__domain")],
        orderable=False,
    )
    total = tables.Column(verbose_name="Total")
    urls__url = tables.Column(verbose_name="Url")
    tags = tables.Column(orderable=False)

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("urls__url", "total", "tags", "search")


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
    tags = tables.Column(orderable=False)
    search = tables.LinkColumn(
        "search",
        text=format_html("<i class='fas fa-search'></i>"),
        args=["domain", A("urls__domain__domain")],
        orderable=False,
    )

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("urls__domain__domain", "total", "tags", "search")


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
