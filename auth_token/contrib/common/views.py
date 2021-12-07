from auth_token.contrib.common.default.views import TokenLogoutView
from auth_token.utils import is_installed_security

if is_installed_security:
    from auth_token.contrib.common.auth_security.views import InputLogMixin, TokenLoginView
    from auth_token.contrib.common.auth_security.views import LoginCodeVerificationView as _LoginCodeVerificationView
else:
    from auth_token.contrib.common.default.views import InputLogMixin, TokenLoginView
    from django.contrib.auth.views import LoginView as _LoginCodeVerificationView


class LoginView(TokenLoginView):
    pass


class LogoutView(TokenLogoutView):
    pass


class LoginCodeVerificationView(InputLogMixin, _LoginCodeVerificationView):
    pass
