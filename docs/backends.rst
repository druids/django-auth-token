.. _backends:

Device authentication using mobile login token
==============================================

``django-auth-token`` library provides a mean to sign in and log in from the device. Unlike casual
authentication method using password on mobile device we don't want to neither store the real password
nor ask user everytime to fill it in. For that reason we store a ``mobile_login_token`` on the device.
This token gets generated from UUID of the device after user logs in using another type of authentication.


Sign in the device
------------------
When user gets authenticated call ``auth_token.models.DeviceKey.objects.get_or_create_token`` method
to get a token. Later save it securely on device key chain.


Log in from the device
----------------------
At first you must update your settings by adding a new authentication method::

    AUTHENTICATION_BACKENDS = (
        ...
        'auth_token.backends.DeviceBackend',
    )


Then when you need to authenticate a user call ``django.contrib.auth.authenticate`` with UUID of the device
and token recieved from ``get_or_create_token`` method during device registration::

    logged_user = authenticate(mobile_device_id=device_uuid, mobile_login_token=mobile_login_token)
