from .base import *  # noqa
from .base import env

# GENERAL
# ------------------------------------------------------------------------------
SECRET_KEY = env(
    "DJANGO_SECRET_KEY",
    default="cLrYrfzAGCtFXLI951Kx7Q7hJHcoAiG8y8dd9PcwJHG9C8QX2u4S9ya5UL8iPFe2",
)
TEST_RUNNER = "django.test.runner.DiscoverRunner"

# CACHES
# ------------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "",
    }
}

# PASSWORDS
# ------------------------------------------------------------------------------
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# TEMPLATES
# ------------------------------------------------------------------------------
TEMPLATES[-1]["OPTIONS"]["loaders"] = [  # type: ignore[index] # noqa F405
    (
        "django.template.loaders.cached.Loader",
        [
            "django.template.loaders.filesystem.Loader",
            "django.template.loaders.app_directories.Loader",
        ],
    )
]

# EMAIL
# ------------------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
