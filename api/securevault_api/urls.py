"""
SecureVault API — Root URL Configuration

Routes:
  /api/auth/register/       — User registration
  /api/auth/token/          — JWT obtain pair (login)
  /api/auth/token/refresh/  — JWT refresh
  /api/vault/               — Vault CRUD (see vault/urls.py)
  /admin/                   — Django admin
"""

from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from vault.views import RegisterView

urlpatterns = [
    # ── Admin ──
    path("admin/", admin.site.urls),

    # ── Auth ──
    path("api/auth/register/", RegisterView.as_view(), name="auth-register"),
    path("api/auth/token/", TokenObtainPairView.as_view(), name="token-obtain"),
    path("api/auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),

    # ── Vault ──
    path("api/vault/", include("vault.urls")),
]
