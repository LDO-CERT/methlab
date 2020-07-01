from django.shortcuts import render
from django.db.models import Count
from methlab.shop.models import Mail
from methlab.shop.tables import AttachmentTable, IocTable, MailTable


def home(request):

    email_count = Mail.objects.count()

    table_m = MailTable(
        Mail.objects.all()
        .values("subject")
        .annotate(total=Count("subject"))
        .order_by("-total"),
        prefix="m_",
    )
    table_m.paginate(page=request.GET.get("m_page", 1), per_page=10)

    table_a = AttachmentTable(
        Mail.objects.all()
        .values("attachments__md5", "attachments__sha256")
        .annotate(total=Count("attachments__md5"))
        .order_by("-total"),
        prefix="a_",
    )
    table_a.paginate(page=request.GET.get("a_page", 1), per_page=10)

    table_i = IocTable(
        Mail.objects.all()
        .values("iocs__ip", "iocs__domain")
        .annotate(total=Count("iocs__ip"))
        .order_by("-total"),
        prefix="i_",
    )
    table_i.paginate(page=request.GET.get("i_page", 1), per_page=10)
    return render(
        request,
        "base.html",
        {
            "table_m": table_m,
            "table_a": table_a,
            "table_i": table_i,
            "email_count": email_count,
        },
    )
