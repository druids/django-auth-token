from django import forms
from django.contrib.auth import login as auth_login
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.forms.utils import ErrorList
from django.http import HttpResponseRedirect
from django.views.generic.base import RedirectView

import import_string
from auth_token.config import settings
from auth_token.contrib.common.views import LoginView as _LoginView
from auth_token.contrib.common.views import LogoutView as _LogoutView
from auth_token.contrib.common.views import LoginCodeVerificationView as _LoginCodeVerificationView
from auth_token.contrib.is_core_auth.forms import LoginCodeVerificationForm
from auth_token.models import Token
from auth_token.utils import login, takeover
from is_core.generic_views import DefaultCoreViewMixin
from is_core.generic_views.mixins import GetCoreObjViewMixin


class LoginView(_LoginView):

    template_name = 'is_core/login.html'


class TwoFactorLoginView(LoginView):

    def _generate_and_send_two_factor_code(self):
        code = import_string(settings.TWO_FACTOR_CODE_GENERATING_FUNCTION)(Token.TWO_FACTOR_CODE_LENGTH)
        import_string(settings.TWO_FACTOR_SENDING_FUNCTION)(self.request.token, code)
        self.request.token.two_factor_code = make_password(code, salt=Token.TWO_FACTOR_CODE_SALT)
        self.request.token.save()

    def _login(self, user, expiration, form):
        login(
            self.request, user, expiration, allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header,
            two_factor_login=True
        )

    def get_success_url(self):
        return '{url}?{redirect_field_name}={value}'.format(
            url=settings.TWO_FACTOR_REDIRECT_URL, redirect_field_name=self.redirect_field_name,
            value=self.get_redirect_url()
        )

    def form_valid(self, form):
        """
        The user has provided valid credentials (this was checked in AuthenticationForm.is_valid()). So now we
        can check the test cookie stuff and log him in.
        """
        self._login(form.get_user(), not form.is_permanent(), form)
        try:
            # send user the code for second part of authentication process
            self._generate_and_send_two_factor_code()
        except ValidationError as err:
            form._errors[forms.forms.NON_FIELD_ERRORS] = ErrorList([err])
            return self.form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())


class LogoutView(_LogoutView):

    template_name = 'is_core/logged_out.html'


class UserTakeover(GetCoreObjViewMixin, DefaultCoreViewMixin, RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        return settings.TAKEOVER_REDIRECT_URL

    def get(self, request, *args, **kwargs):
        user = self.get_obj()
        takeover(request, user)
        return super().get(request, *args, **kwargs)


class LoginCodeVerificationView(_LoginCodeVerificationView):

    template_name = 'is_core/login.html'
    form_class = LoginCodeVerificationForm

    def form_valid(self, form):
        self.log_successful_request()
        auth_login(self.request, form.get_user(), self.request.token.backend)
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        self.log_unsuccessful_request()
        return super().form_invalid(form)
