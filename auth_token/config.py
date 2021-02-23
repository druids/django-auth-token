from django.conf import settings as django_settings
from django.utils.translation import ugettext_lazy as _


DEFAULTS = {
    'COOKIE': True,  # Cookie authorization is allowed
    'COOKIE_NAME': 'Authorization',  # Authorization token cookie name
    'COOKIE_AGE': 60 * 60 * 24 * 7 * 2,  # Age of cookie, in seconds (default: 2 weeks)
    'COOKIE_HTTPONLY': False,  # Scripts can read authorization cookie
    'COOKIE_SECURE': False,  # Cookie can be sent only via HTTPS
    'COOKIE_DOMAIN': None,  # Cookie domain name
    'HEADER': True,  # Header authorization is allowed
    'HEADER_NAME': 'Authorization',  # Authorization token HTTP header name
    'HEADER_TOKEN_TYPE': 'Bearer',  # Type of the token
    'DEFAULT_TOKEN_AGE': 60 * 60,  # Default token expiration time (default: 1 hour)
    'COUNT_USER_PRESERVED_TOKENS': 20,  # Maximum tokens that will be preserved per user
    'TAKEOVER_REDIRECT_URL': '/',  # The path where will be used after takeover another user token
    'TWO_FACTOR_ENABLED': False,  # Two factor authentication is disabled
    'TWO_FACTOR_REDIRECT_URL': 'login-code-verification/',  # The path the user is redirected to after successful two
                                                            # factor authentication
    'TWO_FACTOR_AUTHORIZATION_SLUG': '2FA',  # Second factor authorization
    'TWO_FACTOR_AUTHORIZATION_TITLE': _('Second factor authorization'),
    'TWO_FACTOR_AUTHORIZATION_DESCRIPTION': _('Please insert code for second factor authorization'),
    'TWO_FACTOR_CODE_GENERATING_FUNCTION': 'auth_token.utils.generate_two_factor_key',  # Function which generates
                                                                                        # code for two factor
                                                                                        # authentication
    'TWO_FACTOR_CODE_GENERATING_FUNCTION_LENGTH': 6,  # Default length for two factor code generator function
    'TWO_FACTOR_CODE_SALT': 'auth-token-two-factor',
    'TWO_FACTOR_SENDING_FUNCTION': '',  # Function, which need to be implemented to send the key for second part of
                                        # authorization process to the user
    'RENEWAL_EXEMPT_HEADER': 'X-Authorization-Renewal-Exempt',  # Header name which causes that the token expiration
                                                                # time will not be extended
    'EXPIRATION_HEADER': 'X-Authorization-Expiration',  # Header name which contains information about token expiration
    'MAX_RANDOM_KEY_ITERATIONS': 100,  # Maximum iterations for random key generator
    'HASH_SALT': 'django.auth.token',  # Salt for hash_key function
    'DEFAULT_OTP_AGE': 60 * 60,  # Default OTP expiration time (default: 1 hour),
    'DEFAULT_AUTHORIZATION_REQUEST_AGE': 60 * 60,  # Default authorization request expiration time (default: 1 hour),
    'AUTHORIZATION_REQUEST_PRESERVE_AGE': 60 * 60 * 24 * 7,  # Keep expired authorization requests in database
                                                             # (default: 7 days)
    'AUTHORIZATION_REQUEST_OTP_DEBUG_CODE': None,  # Default code two factor OTP
    'FORM_COOKIE_PERMANENT': False,  # Add permanent checkbox to auth form.
    'OTP_DEFAULT_KEY_GENERATOR': 'auth_token.utils.generate_key',  # Default key generator for OTP
}


class Settings:

    def __getattr__(self, attr):
        if attr not in DEFAULTS:
            raise AttributeError('Invalid AUTH_TOKEN setting: "{}"'.format(attr))

        default = DEFAULTS[attr]
        return getattr(django_settings, 'AUTH_TOKEN_{}'.format(attr), default(self) if callable(default) else default)


settings = Settings()
