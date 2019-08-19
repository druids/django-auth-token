from django import forms
from django.contrib.auth.hashers import make_password
from django.utils.translation import ugettext as _

from is_core.forms.forms import SmartForm

from auth_token.config import settings
from auth_token.contrib.common.forms import AuthenticationCleanMixin, TokenAuthenticationMixin
from auth_token.models import Token


class TokenAuthenticationSmartForm(TokenAuthenticationMixin, AuthenticationCleanMixin, SmartForm):
    pass


class LoginCodeVerificationForm(SmartForm):

    code = forms.CharField(max_length=40, required=True, label=_('code'))

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)

    def _init_code(self, field):
        if settings.TWO_FACTOR_DEBUG_TOKEN_SMS_CODE:
            field.initial = settings.TWO_FACTOR_DEBUG_TOKEN_SMS_CODE

    def get_user(self):
        return self.request.token.user

    def clean_code(self):
        code = self.cleaned_data.get('code')
        if (make_password(code, salt=Token.TWO_FACTOR_CODE_SALT) != self.request.token.two_factor_code
                and (not settings.TWO_FACTOR_DEBUG_TOKEN_SMS_CODE or settings.TWO_FACTOR_DEBUG_TOKEN_SMS_CODE != code)):
            raise forms.ValidationError(_('The inserted value does not correspond to the sent code.'))
        else:
            self.request.token.is_authenticated = True
            self.request.token.save()
        return code
