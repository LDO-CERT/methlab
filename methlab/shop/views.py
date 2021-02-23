import operator
from functools import reduce
from datetime import timedelta
from django.db.models import Q
from django.utils import timezone
from django.http import Http404, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.db.models import Count
from django.db.models.functions import TruncHour
from django.contrib.postgres.search import TrigramSimilarity
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required


from django_pivot.pivot import pivot

from methlab.shop.models import (
    InternalInfo,
    Mail,
    Whitelist,
    Address,
    Flag,
    RESPONSE,
    Attachment,
    Ip,
    Url,
    Domain,
)
from methlab.shop.tables import (
    AttachmentTable,
    IpTable,
    DomainTable,
    MailTable,
    LatestMailTable,
    AddressTable,
    UrlTable,
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
            submission_date__gte=timezone.now() - timedelta(days=10)
        )
        .annotate(thour=TruncHour("submission_date"))
        .order_by()
    )

    record_by_time = pivot(
        qs,
        "thour",
        "official_response",
        "pk",
        aggregation=Count,
        display_transform=lambda x: x.lower().replace(" ", "_"),
    ).order_by("thour")

    # PAGINATE LATEST EMAIL
    table = LatestMailTable(
        Mail.external_objects.prefetch_related(
            "addresses", "ips", "urls", "attachments", "tags"
        ).order_by("-submission_date")[:250],
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


def campaigns(request, campaign_type):
    if campaign_type not in ("subject", "sender"):
        raise Http404("404")

    internal_servers = InternalInfo.objects.all()[0].internal_domains

    sort_by = request.GET.get("sort", "-total")
    if sort_by == "total":
        sort_by = "-{}".format(sort_by)

    if campaign_type == "subject":
        # BY SUBJECT
        mails = (
            Mail.external_objects.exclude(subject__isnull=True)
            .exclude(subject="")
            .values("subject")
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
            .exclude(
                reduce(
                    operator.and_, (Q(address__icontains=x) for x in internal_servers)
                )
            )
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
    ip_wl = Whitelist.objects.filter(type="ip").values_list("value", flat=True)
    url_wl = Whitelist.objects.filter(type="url").values_list("value", flat=True)
    domain_wl = Whitelist.objects.filter(type="domain").values_list("value", flat=True)

    # SORT BY ATTACHMENTS
    a_sort_by = request.GET.get("a-sort", "-total")
    if a_sort_by == "total":
        a_sort_by = "-{}".format(a_sort_by)
    attachments = (
        Mail.external_objects.exclude(attachments__sha256__in=att_wl)
        .exclude(attachments__sha256__isnull=True)
        .values("attachments__md5", "attachments__sha256", "attachments__tags")
        .annotate(total=Count("attachments__md5"))
        .order_by(a_sort_by)
    )
    table_a = AttachmentTable(
        attachments,
        prefix="a-",
    )
    table_a.paginate(page=request.GET.get("a-page", 1), per_page=10)

    # SORT BY IP
    i_sort_by = request.GET.get("i-sort", "-total")
    if i_sort_by == "total":
        i_sort_by = "-{}".format(i_sort_by)
    ips = (
        Mail.external_objects.exclude(
            ips__ip__isnull=True
        )  # .exclude(ips__ip__in=ip_wl)
        .values("ips__ip", "ips__tags")
        .annotate(total=Count("ips"))
        .order_by(i_sort_by)
    )
    table_i = IpTable(ips, prefix="i-")
    table_i.paginate(page=request.GET.get("i-page", 1), per_page=10)

    # SORT BY URL
    u_sort_by = request.GET.get("u-sort", "-total")
    if u_sort_by == "total":
        u_sort_by = "-{}".format(u_sort_by)
    urls = (
        Mail.external_objects.exclude(urls__url__isnull=True)
        .exclude(urls__url__in=url_wl)
        .values("urls__url", "urls__tags", "urls__domain__domain")
        .annotate(total=Count("urls"))
        .order_by(u_sort_by)
    )
    table_u = UrlTable(urls, prefix="u-")
    table_u.paginate(page=request.GET.get("u-page", 1), per_page=10)

    # SORT BY DOMAIN
    d_sort_by = request.GET.get("d-sort", "-total")
    if d_sort_by == "total":
        d_sort_by = "-{}".format(d_sort_by)
    domains = (
        Mail.external_objects.exclude(urls__url__isnull=True)
        .exclude(urls__domain__domain__in=domain_wl)
        .values("urls__domain__domain", "urls__domain__tags")
        .annotate(total=Count("urls__domain__domain"))
        .order_by(d_sort_by)
    )
    table_d = DomainTable(domains, prefix="d-")
    table_d.paginate(page=request.GET.get("d-page", 1), per_page=10)

    return render(
        request,
        "pages/stats.html",
        {
            "table_a": table_a,
            "table_i": table_i,
            "table_u": table_u,
            "table_d": table_d,
        },
    )


def mail_detail(request, pk):
    mail = get_object_or_404(
        Mail.objects.prefetch_related(
            "addresses", "ips", "urls", "attachments", "tags"
        ),
        pk=pk,
    )
    users = get_user_model().objects.all()
    return render(
        request,
        "pages/detail.html",
        {"mail": mail, "users": users, "responses": RESPONSE},
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
        elif method == "ip":
            query = "[ip] {}".format(search_object)
            mails = []
            for ioc in Ip.objects.filter(ip=search_object).distinct():
                for mail in ioc.ips(manager="external_objects").all():
                    mails.append(mail)
        elif method == "url":
            query = "[url] {}".format(search_object)
            mails = []
            for ioc in Url.objects.filter(url=search_object).distinct():
                for mail in ioc.urls(manager="external_objects").all():
                    mails.append(mail)
        elif method == "domain":
            query = "[domain] {}".format(search_object)
            mails = []
            for ioc in Domain.objects.filter(domain=search_object).distinct():
                for url in ioc.url_set.all():
                    for mail in url.urls(manager="external_objects").all():
                        if mail not in mails:
                            mails.append(mail)
        else:
            raise Http404("404")
    else:
        query = request.POST["query"]
        mails = Mail.external_objects.search(query)
    table = LatestMailTable(mails)
    table.paginate(page=request.GET.get("page", 1), per_page=25)
    return render(request, "pages/search.html", {"table": table, "query": query})


@login_required
def tag(request):
    if request.is_ajax():
        mail = request.POST.get("mail")
        tag = request.POST.get("tag")
        op = request.POST.get("op")
        mail = get_object_or_404(Mail, pk=mail)
        if op == "ADD":
            mail.tags.add(tag)
        elif op == "REMOVE":
            mail.tags.remove(tag)
        else:
            raise Http404("404")
        return JsonResponse({"ok": True})
    raise Http404("404")


@login_required
def response(request):
    if request.is_ajax():
        mail = request.POST.get("mail")
        response = request.POST.get("response")
        mail = get_object_or_404(Mail, pk=mail)
        mail.official_response = response
        mail.save()
        return JsonResponse({"ok": True})
    raise Http404("404")


@login_required
def assignee(request):
    if request.is_ajax():
        mail = request.POST.get("mail")
        assignee = request.POST.get("assignee")
        mail = get_object_or_404(Mail, pk=mail)
        user = get_object_or_404(get_user_model(), pk=assignee)
        mail.assignee = user
        mail.save()
        return JsonResponse({"ok": True})
    raise Http404("404")


@login_required
def progress(request):
    if request.is_ajax():
        mail = request.POST.get("mail")
        progress = request.POST.get("progress")
        mail = get_object_or_404(Mail, pk=mail)
        mail.progress = progress
        mail.save()
        return JsonResponse({"ok": True})
    raise Http404("404")


@login_required
def whitelist(request):
    if request.is_ajax():
        item = request.POST.get("item")
        item_type = request.POST.get("item_type")
        op = request.POST.get("op")
        if item_type == "sha256":
            item = get_object_or_404(Attachment, pk=item)
            value = item.sha256
        elif item_type == "domain":
            item = get_object_or_404(Ioc, pk=item)
            value = item.domain
        elif item_type == "ip":
            item = get_object_or_404(Ioc, pk=item)
            value = item.ip
        else:
            raise Http404("404")
        if op == "ADD":
            wl, created = Whitelist.objects.get_or_create(value=value, type=item_type)
        elif op == "REMOVE":
            wl = get_object_or_404(Whitelist, value=value, type=item_type)
            wl.delete()
        else:
            raise Http404("404")
        return JsonResponse({"ok": True})
    raise Http404("404")
