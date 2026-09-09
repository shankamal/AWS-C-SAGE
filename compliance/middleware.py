import base64
import hmac
import os
from dataclasses import dataclass

from django.http import HttpResponse


@dataclass
class BasicUser:
    username: str

    @property
    def is_authenticated(self):
        return True

    def get_username(self):
        return self.username


class BasicAuthMiddleware:
    """Protect C-SAGE without Django's database-backed auth/session stack."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.username = os.getenv("CSAGE_AUTH_USERNAME", "").strip()
        self.password = os.getenv("CSAGE_AUTH_PASSWORD", "")
        self.disable_auth = os.getenv("CSAGE_DISABLE_AUTH", "false").lower() == "true"

    def __call__(self, request):
        if request.path == "/healthz/" or request.path.startswith("/static/"):
            return self.get_response(request)

        if self.disable_auth:
            request.user = BasicUser("local-admin")
            return self.get_response(request)

        if not self.username or not self.password:
            return HttpResponse(
                "C-SAGE authentication is not configured. Set CSAGE_AUTH_USERNAME and CSAGE_AUTH_PASSWORD.",
                status=503,
                content_type="text/plain",
            )

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
                username, password = decoded.split(":", 1)
                if hmac.compare_digest(username, self.username) and hmac.compare_digest(password, self.password):
                    request.user = BasicUser(username)
                    return self.get_response(request)
            except (ValueError, UnicodeDecodeError):
                pass

        response = HttpResponse("Authentication required", status=401, content_type="text/plain")
        response["WWW-Authenticate"] = 'Basic realm="C-SAGE"'
        return response
