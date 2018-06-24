.. _helpers:


Log a user in
-------------

If you have an authenticated user you want to attach to the current request
- this is done with a ``auth_token.utils.login`` function.

.. function:: login(request, user, expiration=True, auth_slug=None, related_objs=None, backend=None, allowed_cookie=True, allowed_header=True)

  * ``request`` - Django request
  * ``user`` - authenticated user
  * ``expiration`` - defines if token is permanent or not
  * ``auth_slug`` - custom tag for your purposes
  * ``related_objs`` - list of related objects
  * ``backend`` - Django authorization backend
  * ``allowed_cookie`` - is allowed to log via cookie
  * ``allowed_header`` - is allowed to log via HTTP header


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

.. function:: logout(request, user)

  * ``request`` - Django request with token and authenticated user
  * ``user`` - takeoved user
