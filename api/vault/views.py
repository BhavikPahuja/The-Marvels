"""
Vault Views — Registration + Zero-Knowledge CRUD

Endpoints:
  POST   /api/auth/register/   — Create a new user account
  GET    /api/vault/           — List all vault entries for the authenticated user
  POST   /api/vault/store/     — Store a new encrypted vault entry
  GET    /api/vault/<uuid>/    — Retrieve a single vault entry
  PUT    /api/vault/<uuid>/    — Update a vault entry
  DELETE /api/vault/<uuid>/    — Delete a vault entry

Security:
  - All vault endpoints require JWT authentication.
  - Users can ONLY access their own entries (queryset filtering + ownership check).
"""

from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .models import VaultEntry
from .serializers import RegisterSerializer, VaultEntrySerializer


# ──────────────────────────────────────────────
# Auth Views
# ──────────────────────────────────────────────

class RegisterView(generics.CreateAPIView):
    """
    POST /api/auth/register/

    Create a new user account. No authentication required.
    Returns the user's id, username, and email on success.
    """

    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "message": "Account created successfully.",
            },
            status=status.HTTP_201_CREATED,
        )


# ──────────────────────────────────────────────
# Vault Views
# ──────────────────────────────────────────────

class VaultEntryListView(generics.ListAPIView):
    """
    GET /api/vault/

    List all vault entries belonging to the authenticated user.
    Returns ciphertext blobs — decryption happens client-side.
    """

    serializer_class = VaultEntrySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return VaultEntry.objects.filter(user=self.request.user)


class VaultEntryCreateView(generics.CreateAPIView):
    """
    POST /api/vault/store/

    Store a new encrypted vault entry. The user is set
    automatically from the JWT token — clients never specify it.
    """

    serializer_class = VaultEntrySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class VaultEntryDetailView(generics.RetrieveAPIView):
    """
    GET /api/vault/<uuid>/

    Retrieve a single vault entry. Only the owner can access it.
    """

    serializer_class = VaultEntrySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "id"

    def get_queryset(self):
        return VaultEntry.objects.filter(user=self.request.user)


class VaultEntryUpdateView(generics.UpdateAPIView):
    """
    PUT /api/vault/<uuid>/

    Update an existing vault entry (e.g., re-encrypt with a new payload).
    Only the owner can update.
    """

    serializer_class = VaultEntrySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "id"

    def get_queryset(self):
        return VaultEntry.objects.filter(user=self.request.user)


class VaultEntryDeleteView(generics.DestroyAPIView):
    """
    DELETE /api/vault/<uuid>/

    Permanently delete a vault entry. Only the owner can delete.
    """

    serializer_class = VaultEntrySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "id"

    def get_queryset(self):
        return VaultEntry.objects.filter(user=self.request.user)
