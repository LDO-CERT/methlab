import django_tables2 as tables
from methlab.shop.models import Attachment, Ioc, Mail


class MailTable(tables.Table):
    class Meta:
        model = Mail
        template_name = "django_tables2/bootstrap4.html"
        fields = ("subject", "total")


class AttachmentTable(tables.Table):
    class Meta:
        model = Attachment
        template_name = "django_tables2/bootstrap4.html"
        fields = ("attachments__md5", "attachments__sha256", "total")


class IocTable(tables.Table):
    class Meta:
        model = Ioc
        template_name = "django_tables2/bootstrap4.html"
        fields = ("iocs__ip", "iocs__domain", "total")
