from django.contrib import admin
from import_export import resources
from django.contrib.auth.models import Group

from .models import (
    Mail,
    Flag,
    InternalInfo,
    Ioc,
    Analyzer,
    Report,
    Whitelist,
    Address,
)
from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from import_export.admin import ImportExportModelAdmin
from django.contrib.contenttypes.admin import GenericTabularInline


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


class AttachmentInline(admin.StackedInline):
    model = Mail.attachments.through
    extra = 0


class FlagInline(admin.TabularInline):
    model = Mail.flags.through
    extra = 0


class IocInline(admin.TabularInline):
    model = Mail.iocs.through
    extra = 0


class AddressesInline(admin.TabularInline, DynamicArrayMixin):
    model = Mail.addresses.through
    extra = 0


class MailAdmin(admin.ModelAdmin, DynamicArrayMixin):
    def has_change_permission(self, request, obj=None):
        return False

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .prefetch_related("tags", "attachments", "flags", "iocs")
        )

    def count_attachments(self, obj):
        return obj.attachments.count()

    def count_iocs(self, obj):
        return obj.iocs.count()

    def tag_list(self, obj):
        return u", ".join(o.name for o in obj.tags.all())

    def flag_list(self, obj):
        return u", ".join([x.name for x in obj.flags.all()])

    inlines = [AttachmentInline, AddressesInline, IocInline, FlagInline]
    list_display = (
        "message_id",
        "parent",
        "subject",
        "count_attachments",
        "count_iocs",
        "tag_list",
        "flag_list",
    )
    search_fields = ["subject"]


class ReportInline(GenericTabularInline):
    model = Report
    extra = 0


class IocAdmin(admin.ModelAdmin, DynamicArrayMixin):
    list_display = ("ip", "domain")
    inlines = [ReportInline]
    search_fields = ["ip", "domain"]


class AnalyzerAdmin(admin.ModelAdmin, DynamicArrayMixin):
    list_display = ("name", "disabled", "supported_types", "priority")
    list_filter = ("priority", "disabled", "supported_types")
    search_fields = ["name"]

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class WhitelistAdmin(admin.ModelAdmin, DynamicArrayMixin):
    list_display = ("value", "type")
    list_filter = ("type",)
    search_fields = ["value"]


class AddressesAdmin(admin.ModelAdmin, DynamicArrayMixin):
    list_filter = ("domain",)
    list_display = ("name", "address", "domain")
    search_fields = ["name", "address"]


class ReportAdmin(admin.ModelAdmin):
    list_display = ("analyzer", "content_type", "object_id")


admin.site.register(InternalInfo, InternalInfoAdmin)
admin.site.register(Mail, MailAdmin)
admin.site.register(Address, AddressesAdmin)
admin.site.register(Flag, FlagAdmin)
admin.site.register(Ioc, IocAdmin)
admin.site.register(Analyzer, AnalyzerAdmin)
admin.site.register(Whitelist, WhitelistAdmin)
admin.site.register(Report, ReportAdmin)

admin.site.unregister(Group)

admin.site.site_header = "MethLab Admin"
admin.site.site_title = "MethLab Admin Portal"
admin.site.index_title = "Welcome to MethLab"
