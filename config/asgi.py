"""
ASGI config for Meth project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/asgi/

"""
import os
import sys
from pathlib import Path

from django.core.asgi import get_asgi_application

ROOT_DIR = Path(__file__).resolve(strict=True).parent.parent
sys.path.append(str(ROOT_DIR / "methlab"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.base")
django_application = get_asgi_application()


async def application(scope, receive, send):
    if scope["type"] == "http":
        await django_application(scope, receive, send)
    else:
        raise NotImplementedError(f"Unknown scope type {scope['type']}")
