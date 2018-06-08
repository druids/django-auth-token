from is_core.forms.forms import SmartForm

from auth_token.contrib.common.forms import AuthenticationCleanMixin, TokenAuthenticationMixin


class TokenAuthenticationSmartForm(TokenAuthenticationMixin, AuthenticationCleanMixin, SmartForm):
    pass
