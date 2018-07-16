from django.conf import settings as django_settings


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
    'MAX_TOKEN_AGE': 60 * 60 * 24 * 7 * 2,  # Max token expiration time (default: 2 weeks)
    'COUNT_USER_PRESERVED_TOKENS': 20,  # Maximum tokens that will be preserved per user
    'TAKEOVER_REDIRECT_URL': '/',  # The path where will be used after takeover another user token
    'RENEWAL_EXEMPT_HEADER': 'X-Authorization-Renewal-Exempt',  # Header name which causes that the token expiration
                                                                # time will not be extended
    'EXPIRATION_HEADER': 'X-Authorization-Expiration',  # Header name which contains information about token expiration
    'MAX_RANDOM_KEY_ITERATIONS': 100,  # Maximum iterations for random key generator
}


class Settings:

    def __getattr__(self, attr):
        if attr not in DEFAULTS:
            raise AttributeError('Invalid AUTH_TOKEN setting: "{}"'.format(attr))

        default = DEFAULTS[attr]
        return getattr(django_settings, 'AUTH_TOKEN_{}'.format(attr), default(self) if callable(default) else default)


settings = Settings()
