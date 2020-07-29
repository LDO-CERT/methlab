from django.conf import settings


def settings_context(_request):
    """Settings available by default to the templates context."""
    return {"DEBUG": settings.DEBUG}
