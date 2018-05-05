Prolog
======

Django-auth-token is library that improved Django framework with token authorization.
Tokens are randomly generated strings which are stored inside database with some information about user
like IP address, user agent, etc. Every token expires automatically according to Django-token-authorization settings.
Advantage is the possibility of deactivation of the token or retrieving the permissions of another user.

Installation
------------

.. code:: bash

    pip install django-auth-token


Configuration
-------------

Add library to the django applications:

.. code-block:: python

    # ...
    INSTALLED_APPS = (
        # ...
        'auth_token',
        # ...
    )
    # ...

Remove django default authorization mixin and use token authorization mixin:


.. code-block:: python

    # ...
    MIDDLEWARE = (
        # ...
        # 'django.contrib.auth.middleware.AuthenticationMiddleware',
        'auth_token.middleware.TokenAuthenticationMiddleware'
        # ...
    )
    # ...

Extra configuration
-------------------

.. code-block:: python

    AUTH_TOKEN_COOKIE_NAME = 'Authorization'  # Authorization token cookie name
    AUTH_TOKEN_COOKIE_AGE =  60 * 60 * 24 * 7 * 2  # Age of cookie, in seconds (default: 2 weeks)
    AUTH_TOKEN_COOKIE_HTTPONLY =  False  # Scripts can read authorization cookie
    AUTH_TOKEN_COOKIE_SECURE =  False  # Cookie can be sent only via HTTPS
    AUTH_TOKEN_COOKIE_DOMAIN =  None  # Cookie domain name
    AUTH_TOKEN_HEADER_NAME =  'Authorization'  # Authorization token HTTP header name
    AUTH_TOKEN_HEADER_TOKEN_TYPE =  'Bearer'  # Type of the token
    AUTH_TOKEN_DEFAULT_TOKEN_AGE =  60 * 60  # Default token expiration time (default: 1 hour)
    AUTH_TOKEN_MAX_TOKEN_AGE =  60 * 60 * 24 * 7 * 2  # Max token expiration time (default: 2 weeks)
    AUTH_TOKEN_COUNT_USER_PRESERVED_TOKENS =  20  # Maximum tokens that will be preserved per user
    AUTH_TOKEN_TAKEOVER_REDIRECT_URL =  '/'  # The path where will be used after takeover another user token
    AUTH_TOKEN_RENEWAL_EXEMPT_HEADER =  'X-Authorization-Renewal-Exempt'  # Header name which causes that the token expiration time will not be extended
    AUTH_TOKEN_EXPIRATION_HEADER = 'X-Authorization-Expiration'  # Header name which contains information about token expiration

Django-is-core
--------------

If you are using django-is-core the tokens are automatically used for user authorization. You can find views and
resources that django-is-core uses in package `auth_token.contrib.is_core`

Django-rests
------------

Django-auth-token supports django-rest-framework too. In the package `auth_token.contrib.rest_framework` you can find
views and authentication class.

There are `auth_token.contrib.rest_framework.wiews.LoginAuthToken` and
`auth_token.contrib.rest_framework.wiews.LoginAuthToken` which you can register to your url patterns
to add endpoints for user login/logout.

You should set `auth_token.contrib.rest_framework.authentication.AuthTokenAuthentication` to your settings:

.. code-block:: python

    REST_FRAMEWORK = {
        # ...
        'DEFAULT_PERMISSION_CLASSES': (
            'rest_framework.permissions.IsAuthenticated',
        )
        # ...
    }