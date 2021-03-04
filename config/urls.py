from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path
from django.views import defaults as default_views
from methlab.shop.views import (
    home,
    mail_detail,
    search,
    campaigns,
    stats,
    tag,
    response,
    assignee,
    progress,
    whitelist,
)
from methlab.shop.models import Mail
from djgeojson.views import GeoJSONLayerView


urlpatterns = [
    path("", home, name="home"),
    path("mail/<int:pk>/", mail_detail, name="mail_detail"),
    path("stats/", stats, name="stats"),
    path("campaigns/<str:campaign_type>/", campaigns, name="campaigns"),
    path("tag", tag, name="tag"),
    path("response", response, name="response"),
    path("assignee", assignee, name="assignee"),
    path("progress", progress, name="progress"),
    path("whitelist", whitelist, name="whitelist"),
    path("search/", search, name="search"),
    path("search/<str:method>/<str:search_object>", search, name="search"),
    path(
        "data.geojson",
        GeoJSONLayerView.as_view(model=Mail),
        name="data",
    ),
    path("accounts/", include("django.contrib.auth.urls")),
    path(settings.ADMIN_URL, admin.site.urls),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
if settings.DEBUG:
    # Static file serving when using Gunicorn + Uvicorn for local web socket development
    urlpatterns += staticfiles_urlpatterns()


if settings.DEBUG:
    urlpatterns += [
        path(
            "400/",
            default_views.bad_request,
            kwargs={"exception": Exception("Bad Request!")},
        ),
        path(
            "403/",
            default_views.permission_denied,
            kwargs={"exception": Exception("Permission Denied")},
        ),
        path(
            "404/",
            default_views.page_not_found,
            kwargs={"exception": Exception("Page not Found")},
        ),
        path("500/", default_views.server_error),
    ]
    if "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar

        urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
