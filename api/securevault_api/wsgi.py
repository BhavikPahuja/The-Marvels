"""
WSGI config for SecureVault API.
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "securevault_api.settings")
application = get_wsgi_application()
