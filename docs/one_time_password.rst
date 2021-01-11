.. _one_time_password:


One time password
-----------------

Library provides way to create random one time password which can be sent via a secure medium. This value can be used for example as a second factor of user authorization.


Create OTP
----------

To create OTP you can use ``auth_token.utils.create_otp`` function. Function create new OTP with unique key and return it. OTP has always set expiration time and only non expired OTP can be authorized.
Returned OTP instance stores secret key (or code) in a hashed format. Therefor secret key accessible only after OTP creation (``create_otp('slug').secret_key``)

.. function:: create_otp(slug, related_objects=None, data=None, key_generator=None, expiration=None, deactivate_old=False)

  * ``slug`` - string for OTP identification.
  * ``related_objects`` - model instances related with OTP.
  * ``data`` - data which will be stored with OTP in the JSON format.
  * ``key_generator`` - OTP key generator.
  * ``expiration`` - OTP expiration time in seconds, default expiration will be used for None value.
  * ``deactivate_old`` - deactivate old tokens with the same slug ane related objects.

Deactivate OTP
--------------

To deactivate OTP function ``auth_token.utils.deactivate_otp``. Only tokens with the same values as a fuction input will be deactivated.

.. function:: create_otp(slug, key=None, related_objects=None)

  * ``slug`` - string for OTP identification.
  * ``key`` - OTP secret key or None.
  * ``related_objects`` - model instances related with OTP.

Check OTP
---------

Function ``auth_token.utils.check_otp`` can be used to check if secret key is valid for some OTP with a given slug. Function return ``True`` if key is valid, ``False`` otherwise.

.. function:: check_otp(slug, key)

  * ``slug`` - string for OTP identification.
  * ``key`` - OTP secret key.

Get valid OTP
-------------

Function ``auth_token.utils.get_valid_otp`` can be used to get valid OTP instance which secret key is valid with the given key. Function return OTP instance if key is valid, ``None`` otherwise.

.. function:: get_valid_otp(slug, key)

  * ``slug`` - string for OTP identification.
  * ``key`` - OTP secret key.


Extend valid OTP
-------------

Function ``auth_token.utils.extend_otp`` can be used to extend OTP expiration. Function returns ``True`` if expiration was extended, ``False`` otherwise. Expiration will be expired only for valid token (token with a given slug must have valid secret key)

.. function:: extend_otp(slug, key, expiration=None)

  * ``slug`` - string for OTP identification.
  * ``key`` - OTP secret key.
  * ``expiration`` - OTP expiration time in seconds, default expiration will be used for None value.

