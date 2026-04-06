from django.conf import settings
from django.contrib import admin, messages
from django.utils import timezone
from .models import VaultEntry
from .honeypot_models import HoneypotEntry


@admin.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    list_display = ("label", "user", "created_at", "updated_at")
    list_filter = ("user", "created_at")
    search_fields = ("label", "user__username")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("-updated_at",)


@admin.register(HoneypotEntry)
class HoneypotEntryAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "category",
        "provider",
        "generator",
        "is_triggered",
        "created_at",
    )
    list_filter = ("category", "generator", "is_triggered", "created_at")
    search_fields = ("user__username", "provider", "honeypot_id")
    list_editable = ("is_triggered",)
    actions = (
        "mark_selected_triggered",
        "trigger_selected_and_send_alerts",
        "clear_selected_trigger",
    )
    readonly_fields = (
        "id",
        "fake_secret",
        "honeypot_id",
        "generator",
        "created_at",
    )
    ordering = ("-created_at",)

    fieldsets = (
        ("Honeypot Info", {
            "fields": ("id", "user", "category", "provider", "generator", "honeypot_id"),
        }),
        ("Fake Credential (Read-Only)", {
            "fields": ("fake_secret",),
            "classes": ("collapse",),
            "description": "⚠️  This is a fake credential. Do not use it anywhere.",
        }),
        ("Trigger Detection", {
            "fields": ("is_triggered", "triggered_at", "triggered_ip"),
        }),
        ("Timestamps", {
            "fields": ("created_at",),
        }),
    )

    @admin.action(description="Mark selected honeypots as triggered")
    def mark_selected_triggered(self, request, queryset):
        now = timezone.now()
        updated = queryset.update(is_triggered=True, triggered_at=now)
        self.message_user(request, f"{updated} honeypot entries marked as triggered.")

    def _extract_client_ip(self, request):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def _dispatch_email_alert(self, entry, source_ip, severity="critical"):
        alert_settings = getattr(settings, "HONEYPOT_ALERT", {})

        if not bool(alert_settings.get("ENABLED", True)):
            return {
                "attempted": False,
                "success": False,
                "reason": "Honeypot alert email is disabled in server settings.",
            }

        recipient_email = (entry.user.email or "").strip()
        if not recipient_email:
            return {
                "attempted": False,
                "success": False,
                "reason": "User has no email configured.",
            }

        from ai_engine.honeypot_alert_api import send_breach_alert

        result = send_breach_alert(
            recipient_email=recipient_email,
            recipient_name=entry.user.get_full_name() or entry.user.username or "User",
            breach_details={
                "honeypot_id": str(entry.honeypot_id),
                "category": entry.category,
                "provider": entry.provider or "vault",
                "triggered_at": entry.triggered_at.isoformat() if entry.triggered_at else timezone.now().isoformat(),
                "triggered_ip": source_ip or "Unknown",
                "severity": severity,
            },
            smtp_host=str(alert_settings.get("SMTP_HOST", "")),
            smtp_port=int(alert_settings.get("SMTP_PORT", 0) or 0),
            smtp_email=str(alert_settings.get("SMTP_EMAIL", "")),
            smtp_password=str(alert_settings.get("SMTP_PASSWORD", "")),
            smtp_from_name=str(alert_settings.get("SMTP_FROM_NAME", "Abhedya Security")),
            smtp_use_tls=bool(alert_settings.get("SMTP_USE_TLS", True)),
            smtp_timeout=int(alert_settings.get("SMTP_TIMEOUT", 0) or 0),
        )

        return {
            "attempted": True,
            "success": bool(result.get("success", False)),
            "reason": result.get("error") if not result.get("success", False) else None,
            "alert_id": result.get("alert_id"),
            "message_id": result.get("message_id"),
        }

    @admin.action(description="Trigger selected honeypots and send styled alert emails")
    def trigger_selected_and_send_alerts(self, request, queryset):
        source_ip = self._extract_client_ip(request)
        now = timezone.now()

        total = queryset.count()
        attempted = 0
        sent = 0
        failed = 0
        skipped = 0
        failure_samples = []

        for entry in queryset.select_related("user"):
            update_fields = ["is_triggered", "triggered_at"]
            entry.is_triggered = True
            entry.triggered_at = now
            if source_ip:
                entry.triggered_ip = source_ip
                update_fields.append("triggered_ip")
            entry.save(update_fields=update_fields)

            email_alert = self._dispatch_email_alert(
                entry=entry,
                source_ip=source_ip,
                severity="critical",
            )

            if not email_alert.get("attempted"):
                skipped += 1
                continue

            attempted += 1
            if email_alert.get("success"):
                sent += 1
            else:
                failed += 1
                if len(failure_samples) < 3:
                    failure_samples.append(
                        f"{entry.user.username}: {email_alert.get('reason') or 'unknown error'}"
                    )

        level = messages.SUCCESS if failed == 0 else messages.WARNING
        self.message_user(
            request,
            (
                f"Processed {total} entries. "
                f"Email attempted: {attempted}, sent: {sent}, failed: {failed}, skipped: {skipped}."
            ),
            level=level,
        )

        if failure_samples:
            self.message_user(
                request,
                "First failures: " + " | ".join(failure_samples),
                level=messages.WARNING,
            )

    @admin.action(description="Clear trigger state for selected honeypots")
    def clear_selected_trigger(self, request, queryset):
        updated = queryset.update(is_triggered=False, triggered_at=None, triggered_ip=None)
        self.message_user(request, f"Trigger state cleared for {updated} honeypot entries.")

    def save_model(self, request, obj, form, change):
        was_triggered = False
        if change and obj.pk:
            previous = HoneypotEntry.objects.filter(pk=obj.pk).values_list("is_triggered", flat=True).first()
            was_triggered = bool(previous)

        # Keep trigger metadata consistent when toggled from admin edit form.
        if obj.is_triggered and not obj.triggered_at:
            obj.triggered_at = timezone.now()
        if obj.is_triggered and not obj.triggered_ip:
            source_ip = self._extract_client_ip(request)
            if source_ip:
                obj.triggered_ip = source_ip
        if not obj.is_triggered:
            obj.triggered_at = None
            obj.triggered_ip = None

        super().save_model(request, obj, form, change)

        if obj.is_triggered and not was_triggered:
            email_alert = self._dispatch_email_alert(
                entry=obj,
                source_ip=obj.triggered_ip,
                severity="critical",
            )
            if email_alert.get("attempted") and email_alert.get("success"):
                self.message_user(
                    request,
                    f"Styled breach alert email sent to {obj.user.email}.",
                    level=messages.SUCCESS,
                )
            elif email_alert.get("attempted"):
                self.message_user(
                    request,
                    f"Honeypot triggered but email failed: {email_alert.get('reason')}",
                    level=messages.WARNING,
                )
            else:
                self.message_user(
                    request,
                    f"Honeypot triggered but email was not attempted: {email_alert.get('reason')}",
                    level=messages.WARNING,
                )
