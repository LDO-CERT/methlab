from django.http import HttpResponse
from django.shortcuts import render
from django.db.models import Count
from taggit.models import Tag
from methlab.shop.models import Mail, Whitelist
from methlab.shop.tables import AttachmentTable, IocTable, MailTable, LatestMailTable


def home(request):

    email_count = Mail.external_objects.count()

    tags = Tag.objects.all()

    suspicious_tags = [x for x in tags if x.name.find("suspicious") != -1]
    suspicious = Mail.external_objects.filter(tags__name__in=suspicious_tags).count()

    malicious_tags = [x for x in tags if x.name.find("malicious") != -1]
    malicious = Mail.external_objects.filter(tags__name__in=malicious_tags).count()

    table_l = table_m = LatestMailTable(
        Mail.external_objects.all().order_by("-date"), prefix="l_",
    )
    table_l.paginate(page=request.GET.get("l_page", 1), per_page=25)

    table_m = MailTable(
        Mail.external_objects.all()
        .values("subject", "pk")
        .annotate(total=Count("subject"))
        .order_by("-total"),
        prefix="m_",
    )
    table_m.paginate(page=request.GET.get("m_page", 1), per_page=10)

    table_a = AttachmentTable(
        Mail.external_objects.all()
        .values("attachments__md5", "attachments__sha256")
        .annotate(total=Count("attachments__md5"))
        .order_by("-total"),
        prefix="a_",
    )
    table_a.paginate(page=request.GET.get("a_page", 1), per_page=10)

    iocs = (
        Mail.external_objects.all()
        .values("iocs__ip", "iocs__domain")
        .annotate(total=Count("iocs"))
        .order_by("-total")
    )

    wl = Whitelist.objects.values_list("value", flat=True)

    table_i = IocTable(
        [x for x in iocs if x["iocs__ip"] not in wl and x["iocs__domain"] not in wl],
        prefix="i_",
    )

    table_i.paginate(page=request.GET.get("i_page", 1), per_page=10)
    return render(
        request,
        "pages/main.html",
        {
            "table_l": table_l,
            "table_m": table_m,
            "table_a": table_a,
            "table_i": table_i,
            "email_count": email_count,
            "suspicious": suspicious,
            "malicious": malicious,
        },
    )


def campaign_detail(request, pk):
    return HttpResponse(pk)


def mail_detail(request, pk):
    return HttpResponse(pk)


def search(request):
    return HttpResponse("search")
