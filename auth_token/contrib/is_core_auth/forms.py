from django import forms
from django.utils.translation import ugettext as _

from is_core.forms.forms import SmartForm

from auth_token.config import settings
from auth_token.contrib.common.forms import AuthenticationCleanMixin, TokenAuthenticationMixin
from auth_token.utils import authorize_login, check_authorization_request


class TokenAuthenticationSmartForm(TokenAuthenticationMixin, AuthenticationCleanMixin, SmartForm):
    pass


class LoginCodeVerificationForm(SmartForm):

    code = forms.CharField(max_length=40, required=True, label=_('code'))

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)

    def _init_code(self, field):
        if settings.AUTHORIZATION_REQUEST_OTP_DEBUG_CODE:
            field.initial = settings.AUTHORIZATION_REQUEST_OTP_DEBUG_CODE

    def get_authorization_request(self):
        return self.request.token.authorization_requests.filter(
            slug=settings.TWO_FACTOR_AUTHORIZATION_SLUG
        ).first('-created_at')

    def get_user(self):
        return self.request.token.user

    def clean_code(self):
        code = self.cleaned_data.get('code')
        authorization_requests = self.get_authorization_request()

        if authorization_requests and check_authorization_request(authorization_requests, otp_secret_key=code):
            authorize_login(self.request.token, self.request)
        else:
            raise forms.ValidationError(_('The inserted value does not correspond to the sent code.'))
        return code
