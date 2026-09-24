"""Identifiers that look like credentials but are not."""

# Content-addressed digests.
IMAGE_DIGEST = "sha256:c81af2393f9a1c7e5b2d8460af13ce92b7d045e63f9a1c7e5b2d8460af13ce92"
GIT_REVISION = "9f2c4e7a1b8d3056f4a29ce1b7d0458e6c81af23"

# A request-signing example from the vendor's documentation.
EXAMPLE_SIGNATURE = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkb2NzIn0.EXAMPLE_SIGNATURE"

# Read at runtime; never hard-coded.
API_KEY_ENV = "SERVICE_API_TOKEN"
DB_PASSWORD_ENV = "DATABASE_PASSWORD"


def headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# Identifier constants whose names mention tokens but whose values are names.
SERVICE_ACCOUNT_TOKEN_CONTROLLER = "serviceaccount-token-controller"
TOKEN_DISCOVERY_FLAG = "discovery-token"
SESSION_SECRET_KEY_NAME = "auth.session.key"
