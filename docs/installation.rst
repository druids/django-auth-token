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

.. attribute:: AUTH_TOKEN_MAX_TOKEN_AGE

  Max token age if concrete token is permanent. Default value is 2 weeks.

.. attribute:: AUTH_TOKEN_COUNT_USER_PRESERVED_TOKENS

  Number of expired tokens that will be preserved for one user. Tokens are removed from the oldest one with ``clean_tokens`` command. Default value is ``20``.

.. attribute:: AUTH_TOKEN_TAKEOVER_REDIRECT_URL

  If you have turned on user takeover setting define URL where will be used after user account takeover. Default value is ``'/'``.

.. attribute:: AUTH_TOKEN_RENEWAL_EXEMPT_HEADER

  HTTP header name that causes that token expiration time will not be extended. Default value is ``'X-Authorization-Renewal-Exempt'``.

.. attribute:: AUTH_TOKEN_EXPIRATION_HEADER

  Header name which contains information about token expiration inside response. Default value is ``'X-Authorization-Expiration'``.
