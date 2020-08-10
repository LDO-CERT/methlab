from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse, Http404
from django.shortcuts import render, get_object_or_404
from django.db.models import Count, Case, When, IntegerField
from django.db.models.functions import TruncHour
from methlab.shop.models import Mail, Whitelist, Address, Flag
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
    flags = Flag.objects.all()
    suspicious_tags = [x for x in flags if x.name.find("suspicious") != -1]
    suspicious = Mail.external_objects.filter(tags__name__in=suspicious_tags).count()
    malicious_tags = [x for x in flags if x.name.find("malicious") != -1]
    malicious = Mail.external_objects.filter(tags__name__in=malicious_tags).count()

    record_by_time = (
        Mail.external_objects.filter(
            submission_date__gte=timezone.now() - timedelta(days=30)
        )
        .annotate(
            thour=TruncHour("submission_date"),
            unknown=Case(
                When(official_response=0, then=1),
                default=0,
                output_field=IntegerField(),
            ),
            spam=Case(
                When(official_response=1, then=1),
                default=0,
                output_field=IntegerField(),
            ),
            ham=Case(
                When(official_response=1, then=2),
                default=0,
                output_field=IntegerField(),
            ),
            phishing=Case(
                When(official_response=1, then=3),
                default=0,
                output_field=IntegerField(),
            ),
            social_engineering=Case(
                When(official_response=1, then=4),
                default=0,
                output_field=IntegerField(),
            ),
            reconnaissance=Case(
                When(official_response=1, then=5),
                default=0,
                output_field=IntegerField(),
            ),
            blackmail=Case(
                When(official_response=1, then=6),
                default=0,
                output_field=IntegerField(),
            ),
            ceo_scam=Case(
                When(official_response=1, then=7),
                default=0,
                output_field=IntegerField(),
            ),
            licit=Case(
                When(official_response=1, then=10),
                default=0,
                output_field=IntegerField(),
            ),
        )
        .values(
            "thour",
            "unknown",
            "spam",
            "ham",
            "phishing",
            "social_engineering",
            "reconnaissance",
            "blackmail",
            "ceo_scam",
            "licit",
        )
    )

    # PAGINATE LATEST EMAIL
    table = LatestMailTable(
        Mail.external_objects.prefetch_related(
            "addresses", "iocs", "attachments", "tags"
        )
        .all()
        .order_by("-submission_date")[:250],
    )
    table.paginate(page=request.GET.get("page", 1), per_page=25)

    return render(
        request,
        "pages/main.html",
        {
            "table": table,
            "email_count": email_count,
            "suspicious": suspicious,
            "malicious": malicious,
            "groups": record_by_time,
        },
    )


def campaign_detail(request, pk):
    return HttpResponse(pk)


def campaigns(request, campaign_type):
    if campaign_type not in ("subject", "sender"):
        raise Http404

    sort_by = request.GET.get("sort", "-total")
    if sort_by == "total":
        sort_by = "-{}".format(sort_by)

    if campaign_type == "subject":
        # SORT BY SUBJECT
        mails = (
            Mail.external_objects.all()
            .values("subject")
            .annotate(total=Count("subject"))
            .filter(total__gt=2)
            .order_by(sort_by)
        )
        table = MailTable(mails)
        table.paginate(page=request.GET.get("page", 1), per_page=20)

    elif campaign_type == "sender":
        # SORT BY SUBJECT
        table = AddressTable(
            Address.objects.filter(mail_addresses__field="from")
            .exclude(address__icontains="@leonardocompany.com")
            .values("mail_addresses__address__address")
            .annotate(total=Count("mail_addresses__address__address"))
            .order_by(sort_by)
            .filter(total__gt=2)
        )
        table.paginate(page=request.GET.get("page", 1), per_page=20)

    return render(
        request,
        "pages/campaigns.html",
        {"table": table, "campaign_type": campaign_type},
    )


def stats(request):
    att_wl = Whitelist.objects.filter(type="sha256").values_list("value", flat=True)
    ioc_wl = Whitelist.objects.filter(type__in=["ip", "domain"]).values_list(
        "value", flat=True
    )

    # SORT BY ATTACHMENTS
    a_sort_by = request.GET.get("a-sort", "-total")
    if a_sort_by == "total":
        a_sort_by = "-{}".format(a_sort_by)
    attachments = (
        Mail.external_objects.exclude(attachments__sha256__in=att_wl)
        .exclude(attachments__sha256__isnull=True)
        .values("attachments__md5", "attachments__sha256")
        .annotate(total=Count("attachments__md5"))
        .order_by(a_sort_by)
    )
    table_a = AttachmentTable(attachments, prefix="a-",)
    table_a.paginate(page=request.GET.get("a-page", 1), per_page=10)

    # SORT BY IOC
    i_sort_by = request.GET.get("i-sort", "-total")
    if i_sort_by == "total":
        i_sort_by = "-{}".format(i_sort_by)
    iocs = (
        Mail.external_objects.all()
        .exclude(iocs__domain__isnull=True, iocs__ip__isnull=True)
        .values("iocs__ip", "iocs__domain")
        .annotate(total=Count("iocs"))
        .order_by(i_sort_by)
    )

    table_i = IocTable(
        [
            x
            for x in iocs
            if x["iocs__ip"] not in ioc_wl and x["iocs__domain"] not in ioc_wl
        ],
        prefix="i-",
    )

    table_i.paginate(page=request.GET.get("i-page", 1), per_page=10)

    return render(
        request, "pages/stats.html", {"table_a": table_a, "table_i": table_i},
    )


def mail_detail(request, pk):
    mail = get_object_or_404(
        Mail.objects.prefetch_related("addresses", "iocs", "attachments", "tags"),
        pk=pk,
    )
    return render(request, "pages/detail.html", {"mail": mail})


def search(request):
    query = request.POST["query"]

    mails = Mail.external_objects.search(query)
    table_l = LatestMailTable(mails, prefix="l_",)
    table_l.paginate(page=request.GET.get("l_page", 1), per_page=25)
    return render(request, "pages/search.html", {"table_l": table_l, "query": query})
