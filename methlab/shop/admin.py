from django.contrib import admin
from import_export import resources
from django.contrib.auth.models import Group
from django.contrib.contenttypes.admin import GenericTabularInline
from .models import (
    Mail,
    Flag,
    InternalInfo,
    Ioc,
    Analyzer,
    Report,
    Whitelist,
    Address,
    Attachment,
)
from django.contrib.postgres import fields
from django_json_widget.widgets import JSONEditorWidget
from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from import_export.admin import ImportExportModelAdmin
from leaflet.admin import LeafletGeoAdmin

from django_celery_beat.models import (
    IntervalSchedule,
    CrontabSchedule,
    PeriodicTask,
    SolarSchedule,
    ClockedSchedule,
)

from taggit.models import Tag

# ########################
# ## TO IMPORT / EXPORT
# ########################


class WhitelistResource(resources.ModelResource):
    class Meta:
        model = Whitelist


class FlagResource(resources.ModelResource):
    class Meta:
        model = Flag


class FlagAdmin(ImportExportModelAdmin):
    resource_class = FlagResource
    list_display = ("name", "color")


class InternalInfoResource(resources.ModelResource):
    class Meta:
        model = InternalInfo


class InternalInfoAdmin(ImportExportModelAdmin, DynamicArrayMixin):
    resource_class = InternalInfoResource
    fieldsets = (
        (None, {"fields": ("name",)}),
        (
            "IMAP",
            {
                "fields": (
                    "imap_server",
                    "imap_username",
                    "imap_password",
                    "imap_folder",
                ),
            },
        ),
        ("Whitelist", {"fields": ("mimetype_whitelist",)}),
        ("Cortex", {"fields": ("cortex_url", "cortex_api")}),
        ("Misp", {"fields": ("misp_url", "misp_api")}),
        ("Security", {"fields": ("security_emails", "honeypot_emails")}),
        (
            "Info",
            {"fields": ("server_list", "vip_list", "vip_domain", "internal_domains")},
        ),
        ("Proxy", {"fields": ("http_proxy", "https_proxy")}),
    )

    def has_add_permission(self, request):
        return (
            False
            if self.model.objects.count() > 0
            else super().has_add_permission(request)
        )

    def has_delete_permission(self, request, obj=None):
        return False


# ########################
# ## MAIL
# ########################


class AttachmentInline(admin.StackedInline):
    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    model = Mail.attachments.through
    extra = 0


class IocInline(admin.TabularInline):
    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    model = Mail.iocs.through
    extra = 0


class AddressesInline(admin.TabularInline, DynamicArrayMixin):
    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    model = Mail.addresses.through
    extra = 0


class MailAdmin(LeafletGeoAdmin, DynamicArrayMixin):

    formfield_overrides = {
        fields.JSONField: {"widget": JSONEditorWidget()},
    }

    readonly_fields = (
        "parent",
        "message_id",
        "subject",
        "date",
        "body",
        "sender_ip_address",
        "to_domains",
        "attachments",
        "dmark",
    )

    exclude = (
        "tags",
        "iocs",
        "addresses",
        "search_vector",
        "attachments_path",
        "eml_path",
    )

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .prefetch_related("tags", "attachments", "iocs")
        )

    inlines = [AttachmentInline, AddressesInline, IocInline]
    list_display = (
        "submission_date",
        "short_id",
        "short_subject",
        "count_attachments",
        "count_iocs",
        "tag_list",
        "dmark",
    )
    list_filter = ("submission_date", "official_response", "progress")
    search_fields = ["subject"]


# ########################
# ## IOC
# ########################


class ReportInline(GenericTabularInline):
    formfield_overrides = {
        fields.JSONField: {"widget": JSONEditorWidget()},
    }

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    model = Report
    extra = 0


class IocAdmin(admin.ModelAdmin, DynamicArrayMixin):
    actions = ["add_to_wl"]
    formfield_overrides = {
        fields.JSONField: {"widget": JSONEditorWidget()},
    }

    def add_to_wl(self, request, queryset):
        for item in queryset:
            if item.ip:
                wl = Whitelist(value=item.ip, type="ip")
            else:
                wl = Whitelist(value=item.domain, type="domain")
            wl.save()

    add_to_wl.short_description = "Add selected iocs to whitelist"

    list_display = ("ip", "domain", "whois")
    inlines = [ReportInline]
    search_fields = ["ip", "domain"]


# ########################
# ## OTHERS
# ########################


class AnalyzerAdmin(admin.ModelAdmin, DynamicArrayMixin):
    list_display = ("name", "disabled", "supported_types", "priority")
    list_filter = ("priority", "disabled", "supported_types")
    search_fields = ["name"]

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class WhitelistAdmin(ImportExportModelAdmin, DynamicArrayMixin):
    list_display = ("value", "type")
    list_filter = ("type",)
    search_fields = ["value"]


class AddressesAdmin(admin.ModelAdmin, DynamicArrayMixin):

    actions = ["add_to_wl"]

    def add_to_wl(self, request, queryset):
        for item in queryset:
            wl = Whitelist(value=item.address, type="address")
            wl.save()

    add_to_wl.short_description = "Add selected addresses to whitelist"

    list_filter = ("domain",)
    list_display = ("name", "address", "domain")
    search_fields = ["name", "address"]


class ReportAdmin(admin.ModelAdmin, DynamicArrayMixin):

    formfield_overrides = {
        fields.JSONField: {"widget": JSONEditorWidget()},
    }

    list_display = ("analyzer", "content_type", "object_id", "taxonomies", "success")


class AttachmentAdmin(admin.ModelAdmin, DynamicArrayMixin):
    actions = ["add_to_wl"]

    def add_to_wl(self, request, queryset):
        for item in queryset:
            wl = Whitelist(value=item.md5, type="md5")
            wl.save()
            wl = Whitelist(value=item.sha256, type="sha256")
            wl.save()

    add_to_wl.short_description = "Add selected hashes to whitelist"

    list_display = ("filename", "md5", "sha256")
    search_fields = ["filename", "md5", "sha256"]


admin.site.register(InternalInfo, InternalInfoAdmin)
admin.site.register(Mail, MailAdmin)
admin.site.register(Address, AddressesAdmin)
admin.site.register(Flag, FlagAdmin)
admin.site.register(Ioc, IocAdmin)
admin.site.register(Analyzer, AnalyzerAdmin)
admin.site.register(Whitelist, WhitelistAdmin)
admin.site.register(Report, ReportAdmin)
admin.site.register(Attachment, AttachmentAdmin)

admin.site.unregister(Group)
admin.site.unregister(Tag)
admin.site.unregister(IntervalSchedule)
admin.site.unregister(CrontabSchedule)
admin.site.unregister(PeriodicTask)
admin.site.unregister(SolarSchedule)
admin.site.unregister(ClockedSchedule)


admin.site.site_header = "MethLab Admin"
admin.site.site_title = "MethLab Admin Portal"
admin.site.index_title = "Welcome to MethLab"
