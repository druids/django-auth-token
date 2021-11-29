from urllib.parse import quote_plus

from django import forms
from django.contrib.auth import login as auth_login
from django.core.exceptions import ValidationError
from django.forms.utils import ErrorList
from django.http import HttpResponseRedirect
from django.views.generic.base import RedirectView
from django.urls import reverse

import import_string
from auth_token.config import settings
from auth_token.contrib.common.views import LoginView as _LoginView
from auth_token.contrib.common.views import LogoutView as _LogoutView
from auth_token.contrib.common.views import LoginCodeVerificationView as _LoginCodeVerificationView
from auth_token.contrib.is_core_auth.forms import LoginCodeVerificationForm
from auth_token.utils import create_authorization_request, grant_authorization_request, login, takeover

from is_core.generic_views.base import DefaultCoreViewMixin
from is_core.generic_views.mixins import GetDjangoObjectCoreViewMixin


class LoginView(_LoginView):

    template_name = 'is_core/login.html'


class TwoFactorLoginView(LoginView):

    def _create_authorization_request(self, user):
        if settings.TWO_FACTOR_ENABLED:
            otp_sender = import_string(settings.TWO_FACTOR_SENDING_FUNCTION)
            authorization_request = create_authorization_request(
                slug=settings.TWO_FACTOR_AUTHORIZATION_SLUG,
                user=user,
                title=settings.TWO_FACTOR_AUTHORIZATION_TITLE,
                description=settings.TWO_FACTOR_AUTHORIZATION_DESCRIPTION,
                authorization_token=self.request.token,
                backend_path=settings.TWO_FACTOR_AUTHORIZATION_BACKEND
            )
            otp_sender(authorization_request, authorization_request.secret_key)

    def _login(self, user, preserve_cookie, form):
        login(
            self.request, user, preserve_cookie=preserve_cookie, allowed_cookie=self.allowed_cookie,
            allowed_header=self.allowed_header, two_factor_login=settings.TWO_FACTOR_ENABLED
        )

    def get_success_url(self):
        return '{url}?{redirect_field_name}={value}'.format(
            url=settings.TWO_FACTOR_REDIRECT_URL,
            redirect_field_name=self.redirect_field_name,
            value=quote_plus(self.get_redirect_url())
        )

    def form_valid(self, form):
        """
        The user has provided valid credentials (this was checked in AuthenticationForm.is_valid()). So now we
        can check the test cookie stuff and log him in.
        """
        user = form.get_user()
        self._login(user, not form.is_permanent(), form)
        try:
            # send user the code for second part of authentication process
            self._create_authorization_request(user)
        except ValidationError as err:
            form._errors[forms.forms.NON_FIELD_ERRORS] = ErrorList([err])
            return self.form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())


class LogoutView(_LogoutView):

    template_name = 'is_core/logged_out.html'


class UserTakeover(GetDjangoObjectCoreViewMixin, DefaultCoreViewMixin, RedirectView):

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
        grant_authorization_request(form.get_authorization_request())
        auth_login(self.request, form.get_user(), self.request.token.backend)
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        self.log_unsuccessful_request()
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        if not self.request.token.is_active:
            return HttpResponseRedirect('{url}?{redirect_field_name}={value}'.format(
                url=reverse('IS:login'), redirect_field_name=self.redirect_field_name,
                value=self.get_redirect_url()
            ))
        elif self.request.token.is_authenticated:
            return HttpResponseRedirect(self.get_success_url())

        return super().dispatch(request, *args, **kwargs)
