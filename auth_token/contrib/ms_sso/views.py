from django.core.exceptions import ImproperlyConfigured
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.utils.translation import gettext
from django.views.generic.base import RedirectView
from django.contrib.auth import authenticate
from django.contrib.auth.views import redirect_to_login

from auth_token.utils import login

from .helpers import get_sign_in_flow, acquire_token_by_auth_code_flow


class MsLogin(RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        sign_flow = get_sign_in_flow()
        sign_flow['next'] = self.request.GET.get('next', '/')
        if not hasattr(self.request, 'session'):
            raise ImproperlyConfigured('Django SessionMiddleware must be enabled to use MS SSO')

        self.request.session['auth_token_ms_sso_auth_flow'] = sign_flow
        return sign_flow['auth_uri']


class MsCallback(RedirectView):

    allowed_cookie = True
    allowed_header = False

    def get(self, *args, **kwargs):
        if not hasattr(self.request, 'session'):
            raise ImproperlyConfigured('Django SessionMiddleware must be enabled to use MS SSO')

        sign_flow = self.request.session.get('auth_token_ms_sso_auth_flow')
        if not sign_flow:
            messages.error(self.request, gettext('Microsoft SSO login was unsuccessful, please try it again'))
            return redirect_to_login('')

        result = acquire_token_by_auth_code_flow(sign_flow, self.request.GET)
        if 'access_token' not in result:
            messages.error(self.request, gettext('Microsoft SSO login was unsuccessful, please try it again'))
            return redirect_to_login(sign_flow['next'])

        user = authenticate(mso_token=result['access_token'])
        if not user:
            messages.error(
                self.request, gettext('Microsoft SSO login was unsuccessful, please use another login method')
            )
            return redirect_to_login(sign_flow['next'])
        else:
            login(
                self.request,
                user,
                allowed_cookie=self.allowed_cookie,
                allowed_header=self.allowed_header,
                two_factor_login=False
            )
            return HttpResponseRedirect(sign_flow['next'])
