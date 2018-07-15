from django.utils.translation import ugettext

from rest_framework.authentication import BaseAuthentication, CSRFCheck
from rest_framework import exceptions

from auth_token.config import settings
from auth_token.utils import get_token_key_from_request


class AuthTokenAuthentication(BaseAuthentication):

    def authenticate(self, request):
        """
        Returns a `User` if the request session currently has a logged in user.
        Otherwise returns `None`.
        """

        # Get the session-based user from the underlying HttpRequest object
        user = getattr(request._request, 'user', None)

        # Unauthenticated, CSRF validation not required
        if not user or not user.is_active:
            if get_token_key_from_request(request)[0] is not None:
                raise exceptions.AuthenticationFailed(ugettext('Invalid authorization token.'))
            return None

        self.enforce_csrf(request)

        # CSRF passed with authenticated user
        return (user, None)

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for session based authentication.
        """
        reason = CSRFCheck().process_view(request, None, (), {})
        if reason:
            # CSRF failed, bail with explicit error message
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)

    def authenticate_header(self, request):
        return settings.HEADER_TOKEN_TYPE
