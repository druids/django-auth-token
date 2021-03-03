.. _helpers:


Log a user in
-------------

If you have an authenticated user you want to attach to the current request
- this is done with a ``auth_token.utils.login`` function.

.. function:: login(request, user, expiration=True, auth_slug=None, related_objs=None, backend=None, allowed_cookie=True, allowed_header=True)

  * ``request`` - Django request.
  * ``user`` - authenticated user.
  * ``auth_slug`` - custom tag for your purposes.
  * ``related_objs`` - list of related objects.
  * ``backend`` - Django authorization backend.
  * ``allowed_cookie`` - is allowed to log via cookie.
  * ``allowed_header`` - is allowed to log via HTTP header.
  * ``two_factor_login`` - login will require second factor authorization.
  * ``expiration`` - expiration time in seconds, for null value setting ``AUTH_TOKEN_DEFAULT_TOKEN_AGE`` is used (1h by default).
  * ``preserve_cookie`` - cookie will not be removed after closing the browser.

Instance of ``AuthorizationToken`` will be automatically added to the request (``request.token``). This token will contain value ``secret_key`` which is unhashed value of ``key`` stored in the database. The ``secret_key`` cannot be get from database.

If login requires second factor request token must be authorized. For this purpose ``auth_token.utils.authorize_login`` can be used.

.. function:: authorize_login(authorization_token, request=None):

  * ``authorization_token`` - authorization token to be authenticated.
  * ``request`` - Django request.


Log a user out
--------------

If you have an authenticated user you want to detach user from the current request
- this is done with a ``auth_token.utils.logout`` function.

.. function:: logout(request)

  * ``request`` - Django request


User takeover
-------------

If you have an authenticated user you want to take session of another user
- this is done with a ``auth_token.utils.takeover`` function.

.. function:: takeover(request, user)

  * ``request`` - Django request with token and authenticated user
  * ``user`` - takeovered user
