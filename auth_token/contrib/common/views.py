from auth_token.contrib.common.default.views import TokenLogoutView

try:
    import security
    from auth_token.contrib.common.auth_security.views import TokenLoginView
except ImportError:
    from auth_token.contrib.common.default.views import TokenLoginView


class LoginView(TokenLoginView):
    pass


class LogoutView(TokenLogoutView):
    pass
