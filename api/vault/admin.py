from django.contrib import admin
from .models import VaultEntry


@admin.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    list_display = ("label", "user", "created_at", "updated_at")
    list_filter = ("user", "created_at")
    search_fields = ("label", "user__username")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("-updated_at",)
