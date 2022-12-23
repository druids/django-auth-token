.. _installation:

Installation
============

Using PIP
---------

You can install django-auth-token via pip:

.. code-block:: console

    $ pip install django-auth-token



Configuration
=============

After installation you must go through these steps:

Required Settings
-----------------

The following variables have to be added to or edited in the project's ``settings.py``:

For using the library you just add ``auth_token`` to ``INSTALLED_APPS`` variable::

    INSTALLED_APPS = (
        ...
        'auth_token',
        ...
    )

Next you must replace ``django.contrib.auth.middleware.AuthenticationMiddleware`` with ``auth_token.middleware.TokenAuthenticationMiddleware``::

    MIDDLEWARE = (
        ...
        # 'django.contrib.auth.middleware.AuthenticationMiddleware',
        'auth_token.middleware.TokenAuthenticationMiddleware',
        ...
    )

Setup
-----

.. attribute:: AUTH_TOKEN_COOKIE

  Cookie is allowed to be used for user authentication. Default value is ``True``.

.. attribute:: AUTH_TOKEN_COOKIE_NAME

  Name of the authorization cookie. Default value is ``'Authorization'``.

.. attribute:: AUTH_TOKEN_COOKIE_AGE

  Age of authorization cookie in seconds. Default value is 2 weeks.

.. attribute:: AUTH_TOKEN_COOKIE_HTTPONLY

  Setting that sets whether the cookie will be set with flag http only. Default value is ``False``.

.. attribute:: AUTH_TOKEN_COOKIE_SECURE

  Setting that sets whether the cookie will be set with flag secure. Default value is ``False``.

.. attribute:: AUTH_TOKEN_COOKIE_DOMAIN

  Cookie domain name. Default value is ``None``.

.. attribute:: AUTH_TOKEN_HEADER

  For user authorization is allowed to use HTTP header. Default value is ``True``.

.. attribute:: AUTH_TOKEN_HEADER_NAME

  Name of the authorization HTTP header. Default value is ``'Authorization'``.

.. attribute:: AUTH_TOKEN_HEADER_TOKEN_TYPE

  Prefix of the authorization token (RFC2617). Default value is ``'Bearer'``. No token prefix will be used If you set ``None``.

.. attribute:: AUTH_TOKEN_DEFAULT_TOKEN_AGE

  Default token age in seconds. Default value is one hour.

.. attribute:: AUTH_TOKEN_LENGTH

  Length of authorization token. Default value is ``40``.

.. attribute:: AUTH_TOKEN_MAX_TOKEN_AGE

  Max token age if concrete token is permanent. Default value is 2 weeks.

.. attribute:: AUTH_TOKEN_COUNT_USER_PRESERVED_TOKENS

  Number of expired tokens that will be preserved for one user. Tokens are removed from the oldest one with ``clean_tokens`` command. Default value is ``20``.

.. attribute:: AUTH_TOKEN_TAKEOVER_REDIRECT_URL

  If you have turned on user takeover setting define URL where will be used after user account takeover. Default value is ``'/'``.

.. attribute:: AUTH_TOKEN_TWO_FACTOR_ENABLED

  Two factor authentication is enabled or disabled. By default value ``False`` is set.

.. attribute:: AUTH_TOKEN_TWO_FACTOR_REDIRECT_URL

  The path the user is redirected to after successful two factor authentication. Default value ``'login-code-verification/'``.

.. attribute:: AUTH_TOKEN_TWO_FACTOR_AUTHORIZATION_SLUG

  Authorization request slug for two factor authorization. Default value is ``'2FA'``.

.. attribute:: AUTH_TOKEN_TWO_FACTOR_SENDING_FUNCTION

  Function, which need to be implemented to send the key for second part of authorization process to the user.

.. attribute:: AUTH_TOKEN_AUTHORIZATION_REQUEST_OTP_DEBUG_CODE

  Default OTP form authorization request.

.. attribute:: AUTH_TOKEN_RENEWAL_EXEMPT_HEADER

  HTTP header name that causes that token expiration time will not be extended. Default value is ``'X-Authorization-Renewal-Exempt'``.

.. attribute:: AUTH_TOKEN_EXPIRATION_HEADER

  Header name which contains information about token expiration inside response. Default value is ``'X-Authorization-Expiration'``.

.. attribute:: AUTH_TOKEN_MAX_RANDOM_KEY_ITERATIONS

  Authorization token key is generated as random string. Because space of random strings is limited there can be collisions. Setting sets number of attempts to generate unique string. Default value is ``100``.

.. attribute:: AUTH_TOKEN_HASH_SALT

  Salt used for hashing keys store in the database (AuthorizationToken key and OneTimePassword key).

.. attribute:: AUTH_TOKEN_DEFAULT_AUTHORIZATION_REQUEST_AGE

  Default authorization request expiration time.. Default value is 1 hour.

.. attribute:: AUTH_TOKEN_AUTHORIZATION_REQUEST_PRESERVE_AGE

  Authorization tokens will not be removed right after its expiration but after X seconds after it. Setting configures the X value. Default value is set to 7 days.

.. attribute:: AUTH_TOKEN_FORM_COOKIE_PERMANENT

  Authorization form will provide way how to store authorization token in cookie after closing the browser.

.. attribute:: AUTH_TOKEN_OTP_DEFAULT_AGE

  Default one time password expiration time. Default value is 1 hour.

.. attribute:: AUTH_TOKEN_OTP_DEFAULT_GENERATOR_CHARACTERS

  Characters which can be used to generate key with default OTP generator. Default value is ``string.digits + string.ascii_letters``.

.. attribute:: AUTH_TOKEN_OTP_DEFAULT_GENERATOR_LENGTH

  Number of characters of key which generates default OTP generator. Default value is ``20``.

.. attribute:: AUTH_TOKEN_OTP_DEFAULT_KEY_GENERATOR

  Path to the default OTP generator. Default value is ``'auth_token.utils.generate_key'``.

.. attribute:: AUTH_TOKEN_OTP_EXPIRATION_RETENTION_PERIOD

  Number of seconds for which active, but expired OTPs will be preserved before deletion. The value should a multiple
  of ``clean_one_time_passwords`` command run period.

.. attribute:: AUTH_TOKEN_AUTHORIZATION_REQUEST_BACKENDS

  List of backends used for authorization request authentication.

.. attribute:: AUTH_TOKEN_MOBILE_DEVICE_SECRET_PASSWORD_LENGTH

  Default length for generated mobile device secret token. Default value is ``64``.

.. attribute:: AUTH_TOKEN_AUTHORIZATION_OTP_BACKEND_DEFAULT_KEY_GENERATOR

  Path to the default OTP key generator of ``auth_token.authorization_request.backends.OTPAuthorizationRequestBackend`` class. Default value is ``auth_token.authorization_request.backends.default_otp_authorization_request_generator``.

.. attribute:: AUTH_TOKEN_AUTHORIZATION_OTP_BACKEND_DEFAULT_KEY_GENERATOR_CHARACTERS

  Characters which can be used to generate key with default key generator of ``auth_token.authorization_request.backends.OTPAuthorizationRequestBackend`` class. Default value is ``string.digits``.

.. attribute:: AUTH_TOKEN_AUTHORIZATION_OTP_BACKEND_DEFAULT_KEY_GENERATOR_LENGTH

   Number of characters of key which generates default key generator of ``auth_token.authorization_request.backends.OTPAuthorizationRequestBackend`` class. Default value is ``6``.

.. attribute:: AUTH_TOKEN_EXPIRATION_DELTA

  Authorization token expiration will be extended during HTTP request, only if original expiration is at least
  "X" seconds older, than new one. Default value is ``0`` seconds, i.e. expiration will be always extended.

.. attribute:: AUTH_TOKEN_TAKEOVER_ENABLED

  Turns on/off takeover functionality. Default value is ``True``, i.e. takeover is enabled.

.. attribute:: AUTH_TOKEN_MS_SSO_APP_ID

  Set AppID for MS SSO authentication. Value must be set with ``auth_token.contrib.ms_sso.backends.MsSsoBackend``

.. attribute:: AUTH_TOKEN_TENANT_ID

  Set TentnatId for MS SSO authentication. Value must be set with ``auth_token.contrib.ms_sso.backends.MsSsoBackend``

MS SSO
------

To allow MS SSO authentization you must install package with msal ``django-auth-token[msal]``, set settings ``AUTH_TOKEN_MS_SSO_APP_ID`` and ``AUTH_TOKEN_TENANT_ID`` and add ``auth_token.contrib.ms_sso.backends.MsSsoBackend`` to ``AUTHENTICATION_BACKENDS`` backends in your Django settings::

    AUTH_TOKEN_MS_SSO_APP_ID = '__ your app id __'
    AUTH_TOKEN_MS_SSO_TENANT_ID = '__ your tenant id __'


Next you must include ``auth_token.contrib.ms_sso.urls`` in your URLS settings::

    from auth_token.contrib.ms_sso import urls as ms_sso_urls
    urlpatterns = static_pyston() + [
        url(r'^', include(ms_sso_urls)),
    ]


Finally you can use MS SSO login via redirect via URL ``/login/mso`` and set callback in MS settings to ``/login/mso/callback``
