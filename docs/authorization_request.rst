.. _authorization_request:


Authorization request
---------------------

Authorization request provides way how authorize insecure user operations.

Create authorization request
----------------------------

To create authorization request you can use ``auth_token.utils.create_authorization_request`` function. Function create new authorization request which can be authorized via specified method. Right now there are two authorization methods OTP or mobile device. OTP can be authorized with knowledge of secret key (code). Mobile device authorization can be done via device ID and secret device token stored in ``MobileDevice`` model.


.. function:: create_authorization_request(type, slug, title, description=None, authorization_token=None, related_objects=None, data=None, otp_key_generator=None, otp_sender=None, mobile_device=None, expiration=None)

  * ``slug`` - string identifier of authorization request.
  * ``user`` - owner of the authorization.
  * ``title`` - human readable string which describes authorization request.
  * ``description`` - longer human readable description of authorization request.
  * ``authorization_token`` - authorization request can be valid only for specific authorization token.
  * ``related_objects`` - related model instances which will be stored with authorization request.
  * ``data`` - data which will be stored with authorization request in the JSON format.
  * ``expiration`` - authorization token expiration time in seconds, default expiration will be used for None value.
  * ``backend_path`` - path authorization request backend class with authentication implementation.


Reset authorization request
---------------------------

To reset authorization request for example with purpose to create new OTP you can use ``auth_token.utils.reset_authorization_request`` function.

.. function:: reset_authorization_request(authorization_request, expiration=None)

  * ``authorization_request`` - authorization request only with type OTP.
  * ``expiration`` - expiration time in seconds.


Check authorization request
---------------------------

To check if authorization request can be granted for user with input secret data can be done with ``auth_token.utils.check_authorization_request`` function. Function returns ``True`` if authorization can be granted, ``False`` elsewhere.

.. function:: check_authorization_request(authorization_request, **kwargs)

  * ``authorization_request`` - authorization request to be authorized.
  * ``**kwargs`` - data used for request authentication (for example otp_secret_key)

Signals
-------

If authorization request is denied or granted receiver registered to one of Django signals are automatically called:

  * ``auth_token.signals.authorization_granted``
  * ``auth_token.signals.authorization_denied``
  * ``auth_token.signals.authorization_cancelled``

The receivers can be registered on a specific slug which is used as a Django signal sender::

    authorization_granted.connect(receiver, sender='2FA')


Grant authorization request
---------------------------

Function ``auth_token.utils.grant_authorization_request`` is used to grant authorization request. Only authorization in ``WAITING`` state can be granted.

.. function:: grant_authorization_request(authorization_request, **kwargs)

  * ``authorization_request`` - authorization request to grant.
  * ``**kwargs`` - custom data which will be send to the signal.

Deny authorization request
--------------------------

Function ``auth_token.utils.deny_authorization_request`` is used to deny authorization request. Only authorization in ``WAITING`` state can be denied.

.. function:: deny_authorization_request(authorization_request, **kwargs)

  * ``authorization_request`` - authorization request to deny.
  * ``**kwargs`` - custom data which will be send to the signal.

Cancel authorization request
----------------------------

Function ``auth_token.utils.cancel_authorization_request`` is used to cancel authorization request. Only authorization in ``WAITING`` state can be cancelled.

.. function:: cancel_authorization_request(authorization_request, **kwargs)

  * ``authorization_request`` - authorization request to deny.
  * ``**kwargs`` - custom data which will be send to the signal.

Authorization request backend
-----------------------------

``auth_token.authorization_request.backend.BaseAuthorizationRequestBackend`` is abstract class which is used for implementation concrete logic for authorization request authentication.::

Library provides two classes which implements it:

* ``auth_token.authorization_request.backend.OTPAuthorizationRequestBackend`` - autentication via OTP
* ``auth_token.authorization_request.backend.MobileDeviceAuthorizationRequestBackend`` - autentication via mobile device

