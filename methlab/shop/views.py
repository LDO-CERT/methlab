from django.http import HttpResponse, Http404
from django.shortcuts import render, get_object_or_404
from django.db.models import Count
from taggit.models import Tag
from methlab.shop.models import Mail, Whitelist, Address
from methlab.shop.tables import (
    AttachmentTable,
    IocTable,
    MailTable,
    LatestMailTable,
    AddressTable,
)


def home(request):
    # COUNT MAIL
    email_count = Mail.external_objects.count()
    tags = Tag.objects.all()
    suspicious_tags = [x for x in tags if x.name.find("suspicious") != -1]
    suspicious = Mail.external_objects.filter(tags__name__in=suspicious_tags).count()
    malicious_tags = [x for x in tags if x.name.find("malicious") != -1]
    malicious = Mail.external_objects.filter(tags__name__in=malicious_tags).count()

    # PAGINATE LATEST EMAIL
    table_l = LatestMailTable(
        Mail.external_objects.prefetch_related(
            "addresses", "iocs", "attachments", "tags", "flags"
        )
        .all()
        .order_by("-date"),
        prefix="l_",
    )
    table_l.paginate(page=request.GET.get("l_page", 1), per_page=25)

    return render(
        request,
        "pages/main.html",
        {
            "table_l": table_l,
            "email_count": email_count,
            "suspicious": suspicious,
            "malicious": malicious,
        },
    )


def campaign_detail(request, pk):
    return HttpResponse(pk)


def campaigns(request, type):
    wl = Whitelist.objects.values_list("value", flat=True)

    if type not in ("subject", "sender"):
        raise Http404

    if type == "subject":
        # SORT BY SUBJECT
        table = MailTable(
            Mail.external_objects.all()
            .values("subject")
            .annotate(total=Count("subject"))
            .filter(total__gt=2)
            .order_by("-total"),
        )
        table.paginate(page=request.GET.get("page", 1), per_page=20)

    elif type == "sender":
        # SORT BY SUBJECT
        table = AddressTable(
            Address.objects.filter(mail_addresses__field="from")
            .exclude(address__icontains="@leonardocompany.com")
            .values("mail_addresses__address__address")
            .annotate(total=Count("mail_addresses__address__address"))
            .order_by("-total")
            .filter(total__gt=2)
        )
        table.paginate(page=request.GET.get("page", 1), per_page=20)

    return render(request, "pages/stats.html", {"table": table, "type": type},)


def stats(request):
    wl = Whitelist.objects.values_list("value", flat=True)

    # SORT BY ATTACHMENTS
    table = AttachmentTable(
        Mail.external_objects.all()
        .values("attachments__md5", "attachments__sha256")
        .annotate(total=Count("attachments__md5"))
        .order_by("-total"),
    )
    table.paginate(page=request.GET.get("page", 1), per_page=10)

    # SORT BY IOC
    iocs = (
        Mail.external_objects.all()
        .values("iocs__ip", "iocs__domain")
        .annotate(total=Count("iocs"))
        .order_by("-total")
    )

    table = IocTable(
        [x for x in iocs if x["iocs__ip"] not in wl and x["iocs__domain"] not in wl],
    )
    table.paginate(page=request.GET.get("page", 1), per_page=10)

    return render(request, "pages/stats.html", {"table": table, "type": type},)


def mail_detail(request, pk):
    mail = get_object_or_404(
        Mail.objects.prefetch_related(
            "addresses", "iocs", "attachments", "tags", "flags"
        ),
        pk=pk,
    )
    return render(request, "pages/detail.html", {"mail": mail})


def search(request):
    query = request.POST["query"]

    mails = Mail.external_objects.search(query)
    table_l = LatestMailTable(mails, prefix="l_",)
    table_l.paginate(page=request.GET.get("l_page", 1), per_page=25)
    return render(request, "pages/search.html", {"table_l": table_l, "query": query})
