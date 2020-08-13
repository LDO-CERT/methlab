from django.utils import timezone
from datetime import timedelta

from django.http import HttpResponse, Http404
from django.shortcuts import render, get_object_or_404
from django.db.models import Sum, IntegerField, Value, Count
from django.db.models.functions import TruncHour
from django.contrib.postgres.search import TrigramSimilarity
from django.contrib.auth import get_user_model

from django_pivot.pivot import pivot

from methlab.shop.models import (
    Mail,
    Whitelist,
    Address,
    Flag,
    RESPONSE,
    Attachment,
    Ioc,
)
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

    qs = (
        Mail.external_objects.filter(
            submission_date__gte=timezone.now() - timedelta(days=30)
        )
        .annotate(thour=TruncHour("submission_date"))
        .order_by("-submission_date")
    )

    record_by_time = pivot(
        qs,
        "thour",
        "official_response",
        Value(1, IntegerField()),
        default=0,
        aggregation=Sum,
        display_transform=lambda x: x.lower().replace(" ", "_"),
    )

    # PAGINATE LATEST EMAIL
    table = LatestMailTable(
        Mail.external_objects.prefetch_related(
            "addresses", "iocs", "attachments", "tags"
        )
        .exclude(subject__isnull=True)
        .exclude(subject="")
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
        # BY SUBJECT
        mails = (
            Mail.external_objects.exclude(subject__isnull=True)
            .exclude(subject="")
            .annotate(total=Count("subject"))
            .values("subject", "slug_subject", "total")
            .filter(total__gt=2)
            .order_by(sort_by)
        )
        table = MailTable(mails)
        table.paginate(page=request.GET.get("page", 1), per_page=20)

    elif campaign_type == "sender":
        # BY FROM MAIL ADDRESS
        table = AddressTable(
            Address.objects.filter(mail_addresses__field="from")
            .exclude(address__icontains="@leonardocompany.com")
            .values("mail_addresses__address__address")
            .annotate(total=Count("mail_addresses__address__address"))
            .filter(total__gt=2)
            .order_by(sort_by)
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
    users = get_user_model().objects.all()
    responses = [x[1] for x in RESPONSE]
    return render(
        request,
        "pages/detail.html",
        {"mail": mail, "users": users, "responses": responses},
    )


def search(request, method=None, search_object=None):
    if search_object:
        query = None
        if method == "mail":
            query = "[MAIL] {}".format(search_object)
            mails = []
            for address in Address.objects.filter(
                mail_addresses__field="from", address=search_object
            ).distinct():
                for mail in address.addresses(manager="external_objects").all():
                    mails.append(mail)
        elif method == "subject":
            query = "[SUBJECT] {}".format(search_object)
            mails = (
                Mail.external_objects.annotate(
                    similarity=TrigramSimilarity("slug_subject", search_object)
                )
                .filter(similarity__gt=0.3)
                .order_by("-similarity")
            )
        elif method == "attachment":
            query = "[SHA256] {}".format(search_object)
            mails = []
            for attachment in Attachment.objects.filter(
                sha256=search_object
            ).distinct():
                for mail in attachment.attachments(manager="external_objects").all():
                    mails.append(mail)
        elif method == "ioc":
            query = "[ioc] {}".format(search_object)
            mails = []
            for ioc in Ioc.objects.filter(domain=search_object).distinct():
                for mail in ioc.iocs(manager="external_objects").all():
                    mails.append(mail)
        else:
            raise Http404("404")
    else:
        query = request.POST["query"]
        mails = Mail.external_objects.search(query)
    table = LatestMailTable(mails)
    table.paginate(page=request.GET.get("page", 1), per_page=25)
    return render(request, "pages/search.html", {"table": table, "query": query})
