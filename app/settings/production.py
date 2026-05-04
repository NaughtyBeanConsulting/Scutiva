from .base import *


DEBUG = False


def _dynamic_custom_domain_hosts_enabled():
	raw_value = (env_str("ALLOW_DYNAMIC_CUSTOM_DOMAIN_HOSTS", "0") or "0").strip().lower()
	return raw_value not in {"0", "false", "no", "off"}


ALLOWED_HOSTS = build_allowed_hosts(allow_wildcard=_dynamic_custom_domain_hosts_enabled())
CSRF_TRUSTED_ORIGINS = build_csrf_trusted_origins([host for host in ALLOWED_HOSTS if host != "*"])

EMAIL_BACKEND = env_str("EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend")
SECURE_SSL_REDIRECT = False
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
X_FRAME_OPTIONS = "DENY"