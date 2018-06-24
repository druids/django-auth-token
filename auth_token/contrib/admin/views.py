from auth_token.contrib.common.views import LoginView as _LoginView, LogoutView as _LogoutView


class LoginView(_LoginView):

    template_name = 'admin/login.html'


class LogoutView(_LogoutView):
    pass
