from django import forms
from django.contrib.auth.hashers import make_password
from django.utils.translation import ugettext as _

from auth_token.contrib.common.forms import AuthenticationCleanMixin, TokenAuthenticationMixin
from auth_token.models import Token
from is_core.forms.forms import SmartForm


class TokenAuthenticationSmartForm(TokenAuthenticationMixin, AuthenticationCleanMixin, SmartForm):
    pass


class LoginCodeVerificationForm(SmartForm):

    code = forms.CharField(max_length=40, required=True, label=_('code'))

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)

    def get_user(self):
        return self.request.token.user

    def clean_code(self):
        code = self.cleaned_data.get('code')
        if make_password(code, salt=Token.TWO_FACTOR_CODE_SALT) != self.request.token.two_factor_code:
            raise forms.ValidationError(_('The inserted value does not correspond to the sent code.'))
        else:
            self.request.token.is_authenticated = True
            self.request.token.save()
        return code
