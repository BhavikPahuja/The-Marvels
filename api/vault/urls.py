"""
Vault URL Configuration

Routes:
  GET    /api/vault/           — List all entries
  POST   /api/vault/store/     — Store a new entry
  GET    /api/vault/<uuid>/    — Retrieve single entry
  PUT    /api/vault/<uuid>/    — Update entry
  DELETE /api/vault/<uuid>/    — Delete entry
"""

from django.urls import path
from .views import (
    VaultEntryListView,
    VaultEntryCreateView,
    VaultEntryDetailView,
    VaultEntryUpdateView,
    VaultEntryDeleteView,
)

urlpatterns = [
    path("", VaultEntryListView.as_view(), name="vault-list"),
    path("store/", VaultEntryCreateView.as_view(), name="vault-store"),
    path("<uuid:id>/", VaultEntryDetailView.as_view(), name="vault-detail"),
    path("<uuid:id>/update/", VaultEntryUpdateView.as_view(), name="vault-update"),
    path("<uuid:id>/delete/", VaultEntryDeleteView.as_view(), name="vault-delete"),
]
