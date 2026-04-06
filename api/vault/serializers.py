"""
Vault Serializers — Registration + VaultEntry CRUD
"""

from django.contrib.auth.models import User
from rest_framework import serializers

from .models import VaultEntry


# ──────────────────────────────────────────────
# Auth Serializers
# ──────────────────────────────────────────────

class RegisterSerializer(serializers.ModelSerializer):
    """
    Handles user registration with password hashing.
    Returns the created user's id, username, and email.
    """

    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={"input_type": "password"},
        help_text="Minimum 8 characters.",
    )
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password")
        read_only_fields = ("id",)

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
        )
        return user


# ──────────────────────────────────────────────
# Vault Serializers
# ──────────────────────────────────────────────

class VaultEntrySerializer(serializers.ModelSerializer):
    """
    Serializes VaultEntry data for the API.
    The `user` field is set automatically from the JWT request —
    clients never specify it.
    """

    class Meta:
        model = VaultEntry
        fields = (
            "id",
            "label",
            "ciphertext",
            "iv",
            "salt",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    def validate_ciphertext(self, value):
        """Ensure ciphertext is not empty."""
        if not value or not value.strip():
            raise serializers.ValidationError("Ciphertext cannot be empty.")
        return value

    def validate_iv(self, value):
        """Ensure IV is not empty."""
        if not value or not value.strip():
            raise serializers.ValidationError("IV cannot be empty.")
        return value

    def validate_salt(self, value):
        """Ensure salt is not empty."""
        if not value or not value.strip():
            raise serializers.ValidationError("Salt cannot be empty.")
        return value
