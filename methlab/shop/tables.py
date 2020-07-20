import django_tables2 as tables
from django_tables2.utils import A
from methlab.shop.models import Attachment, Ioc, Mail


class MailTable(tables.Table):
    total = tables.Column(verbose_name="Total")

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("subject", "total")


class LatestMailTable(tables.Table):
    link = tables.LinkColumn("mail_detail", text=">>>", args=[A("pk")], orderable=False)

    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = (
            "short_subject",
            "flag_list",
            "tag_list",
            "count_attachments",
            "count_iocs",
        )


class AttachmentTable(tables.Table):
    total = tables.Column(verbose_name="Total")
    attachments__md5 = tables.Column(verbose_name="MD5")
    attachments__sha256 = tables.Column(verbose_name="SHA256")

    class Meta:
        model = Attachment
        template_name = "django_tables2/bootstrap4.html"
        fields = ("attachments__md5", "attachments__sha256", "total")


class IocTable(tables.Table):
    total = tables.Column(verbose_name="Total")
    iocs__ip = tables.Column(verbose_name="Ip")
    iocs__domain = tables.Column(verbose_name="Domain")

    class Meta:
        model = Ioc
        template_name = "django_tables2/bootstrap4.html"
        fields = ("iocs__ip", "iocs__domain", "total")
