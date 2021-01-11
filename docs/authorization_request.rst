.. _authorization_request:


Authorization request
---------------------

Authorization request provides way how authorize insecure user operations.

Create authorization request
----------------------------

To create authorization request you can use ``auth_token.utils.create_authorization_request`` function. Function create new authorization request which can be authorized via specified method. Right now there are two authorization methods OTP or mobile device. OTP can be authorized with knowledge of secret key (code). Mobile device authorization can be done via device ID and secret device token stored in ``MobileDevice`` model.


.. function:: create_authorization_request(type, slug, title, description=None, authorization_token=None, related_objects=None, data=None, otp_key_generator=None, otp_sender=None, mobile_device=None, expiration=None)

  * ``type`` - authorization request type. It is value of ``auth_token.enums.AuthorizationRequestType`` enum. Values are ``OTP`` or ``MOBILE_DEVICE``.
  * ``slug`` - string identifier of authorization request.
  * ``user`` - owner of the authorization.
  * ``title`` - human readable string which describes authorization request.
  * ``description`` - longer human readable description of authorization request.
  * ``data`` - data which will be stored with authorization request in the JSON format.
  * ``otp_key_generator`` - function which generates OTP code. For null value default generator is used. Value is used only for ``OTP`` authorization type.
  * ``otp_sender`` - function sends OTP code to the user. Value is used only for ``OTP`` authorization type. Function receives two arguments ``auhorization_request`` and ``otp_code``.
  * ``mobile_device`` - mobile device instance which can authorize the request.
  * ``expiration`` - authorization token expiration time in seconds, default expiration will be used for None value.


Create new OTP to authorization request
---------------------------------------

To create new OTP to authorization request you can use ``auth_token.utils.authorization_create_new_otp`` function. It generates new OTP for waiting request in type ``AuthorizationRequestType.OTP`` and increase its expiration.

.. function:: check_authorization_request(request, authorization_request, mobile_device_id=None, mobile_login_token=None, otp_secret_key=None)

  * ``authorization_request`` - authorization request only with type OTP.
  * ``otp_key_generator``  - function which generates OTP code. For null value default generator is used.
  * ``expiration`` - expiration time in seconds. Empty value means that original expiration time will be used.


Check authorization request
---------------------------

To check if authorization request can be granted for user with input secret data can be done with ``auth_token.utils.check_authorization_request`` function. Function returns ``True`` if authorization can be granted, ``False`` elsewhere.

.. function:: check_authorization_request(request, authorization_request, mobile_device_id=None, mobile_login_token=None, otp_secret_key=None)

  * ``authorization_request`` - authorization request to be authorized.
  * ``mobile_device_id`` - UUID of mobile device which will authorize the request. Input is only used for ``MOBILE_DEVICE`` authorization request type.
  * ``mobile_login_token`` - secret token mobile device which will authorize the request. Input is only used for ``MOBILE_DEVICE`` authorization request type.
  * ``otp_secret_key`` - secret key of OTP. Input is only used for ``OTP`` authorization request type.

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

.. function:: grant_authorization_request(authorization_request)

  * ``authorization_request`` - authorization request to grant.

Deny authorization request
--------------------------

Function ``auth_token.utils.deny_authorization_request`` is used to deny authorization request. Only authorization in ``WAITING`` state can be denied.

.. function:: deny_authorization_request(authorization_request)

  * ``authorization_request`` - authorization request to deny.

Cancel authorization request
----------------------------

Function ``auth_token.utils.cancel_authorization_request`` is used to cancel authorization request. Only authorization in ``WAITING`` state can be cancelled.

.. function:: cancel_authorization_request(authorization_request)

  * ``authorization_request`` - authorization request to deny.
