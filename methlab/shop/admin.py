from django.contrib import admin
from import_export import resources

from .models import Mail, Attachment, Flag, InternalInfo, Ioc
from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from import_export.admin import ImportExportModelAdmin


class FlagResource(resources.ModelResource):
    class Meta:
        model = Flag


class FlagAdmin(ImportExportModelAdmin):
    resource_class = FlagResource


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
        ("Misp", {"fields": ("mips_url", "misp_api")}),
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
    model = Attachment
    extra = 0


class FlagInline(admin.TabularInline):
    model = Mail.flags.through
    extra = 0


class IocInline(admin.TabularInline):
    model = Mail.iocs.through
    extra = 0


class AddressesInline(admin.TabularInline):
    model = Mail.addresses.through
    extra = 0


class MailAdmin(admin.ModelAdmin):
    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .prefetch_related("tags", "attachment_set", "flags", "iocs")
        )

    def count_attachments(self, obj):
        return obj.attachment_set.count()

    def count_iocs(self, obj):
        return obj.iocs.count()

    def tag_list(self, obj):
        return u", ".join(o.name for o in obj.tags.all())

    def flag_list(self, obj):
        return u", ".join([x.name for x in obj.flags.all()])

    inlines = [AttachmentInline, AddressesInline, IocInline, FlagInline]
    readonly_fields = (
        "message_id",
        "subject",
        "received",
        "headers",
        "defects",
        "defects_categories",
        "text_plain",
        "text_not_managed",
        "body",
        "body_plain",
    )
    list_display = (
        "message_id",
        "parent",
        "subject",
        "count_attachments",
        "count_iocs",
        "tag_list",
        "flag_list",
    )


class AttachmentAdmin(admin.ModelAdmin):
    list_display = ("filename", "filepath")


class IocAdmin(admin.ModelAdmin, DynamicArrayMixin):
    list_display = ("ip", "domain", "whitelisted")


admin.site.register(InternalInfo, InternalInfoAdmin)
admin.site.register(Mail, MailAdmin)
admin.site.register(Flag, FlagAdmin)
admin.site.register(Ioc, IocAdmin)
admin.site.register(Attachment, AttachmentAdmin)
