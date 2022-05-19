import random
import re
import string

from datetime import timedelta
from functools import reduce

from operator import and_ as AND

import import_string

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings as django_settings
from django.contrib.auth import _get_backends, load_backend
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.middleware.csrf import rotate_token
from django.utils.crypto import salted_hmac
from django.utils.timezone import now

from .config import settings
from .enums import AuthorizationRequestState, AuthorizationRequestResult
from .signals import authorization_denied, authorization_granted, authorization_cancelled

from ipware.ip import get_client_ip


try:
    import security  # noqa: F401
    is_installed_security = True
except ImportError:
    is_installed_security = False


def _load_request_backend(path):
    return import_string(path)


def get_authorization_request_backends():
    return {
        backend_path: _load_request_backend(backend_path)
        for backend_path in settings.AUTHORIZATION_REQUEST_BACKENDS
    }


def get_authorization_backend(path, raise_exception=False):
    backends = get_authorization_request_backends()

    backend = backends.get(path, None)
    if not backend and raise_exception:
        raise ImproperlyConfigured('Missing authorization request backend with path {}'.format(path))
    return backend() if backend else None


def get_auth_token_age(request, user, auth_slug):
    return import_string(settings.AGE_CALLBACK)(request, user, auth_slug) if settings.AGE_CALLBACK else None


def compute_expires_at(expiration):
    """
    Compute expires at datetime from expiration in seconds.
    Args:
        expiration: expiration time in seconds.

    Returns:
        datetime value
    """
    return now() + timedelta(seconds=expiration)


def hash_key(key, salt=None):
    """
    Hash input key with HMAC. It is used constant SALT defined in configuration.
    It is used algorithm defined in Django DEFAULT_HASHING_ALGORITHM setting
    Django SECRET_KEY is used as a secret.
    Args:
        key: value to hash
        salt: salt value

    Returns:
        hashed value
    """
    return salted_hmac(
        settings.HASH_SALT,
        key,
        secret='|'.join((salt or '', django_settings.SECRET_KEY)),
        algorithm=django_settings.DEFAULT_HASHING_ALGORITHM,
    ).hexdigest()


def header_name_to_django(header_name):
    """
    Convert header into Django format with HTTP prefix.
    Args:
        header_name: HTTP header format (ex. X-Authorization)

    Returns:
        django header format (ex. HTTP_X_AUTHORIZATION)
    """
    return '_'.join(('HTTP', header_name.replace('-', '_').upper()))


def generate_key(characters=string.ascii_letters + string.digits, length=20):
    """
    Generate random string with given characters and length.
    Args:
        characters: characters used for key generator.
        length: key length.

    Returns:
        generated random key.
    """
    return ''.join(random.choices(characters, k=length))


def otp_key_generator_factory(characters, length):
    """
    Factory for random OTP key generator
    Args:
        characters: characters which will be used to generate OTP key
        length: length of generated OTP key

    Returns:

    """
    def _generate_otp_key():
        return generate_key(
            characters=characters, length=length
        )
    return _generate_otp_key


generate_otp_key = otp_key_generator_factory(
    characters=settings.OTP_DEFAULT_GENERATOR_CHARACTERS, length=settings.OTP_DEFAULT_GENERATOR_LENGTH
)


def login(request, user, auth_slug=None, related_objs=None, backend=None, allowed_cookie=True,
          allowed_header=True, two_factor_login=False, expiration=None, preserve_cookie=False,
          mobile_device=None):
    """
    Persist token into database. Token is stored inside cookie therefore is not necessary
    reauthenticate user for every request.
    Args:
        request: Django HTTP request instance
        user: user to login.
        auth_slug: slug stored with authorization token.
        related_objs: django model instances shored with authorization token.
        backend: backend which was used for authorization.
        allowed_cookie: token can be used with the cookies.
        allowed_header: token can be used with the HTTP headers.
        two_factor_login: token will require second factor.
        expiration: expiration time in seconds.
        preserve_cookie: keep cookie after browser closing.
        mobile_device: mobile device which was used for authorization.

    Returns:
        new authorization token which contains secret_key.
    """
    from auth_token.models import AuthorizationToken, compute_authorization_token_expires_at

    related_objs = related_objs if related_objs is not None else ()

    if user is None:
        user = request.user

    try:
        backend = backend or user.backend
    except AttributeError:
        backends = _get_backends(return_tuples=True)
        if len(backends) == 1:
            _, backend = backends[0]
        else:
            raise ValueError(
                'You have multiple authentication backends configured and '
                'therefore must provide the `backend` argument or set the '
                '`backend` attribute on the user.'
            )
    token = AuthorizationToken.objects.create(
        user=user,
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:256],
        auth_slug=auth_slug,
        ip=get_client_ip(request)[0],
        backend=backend,
        allowed_cookie=allowed_cookie,
        allowed_header=allowed_header,
        is_authenticated=not two_factor_login,
        expires_at=compute_authorization_token_expires_at(
            expiration if expiration is not None else get_auth_token_age(request, user, auth_slug)),
        preserve_cookie=preserve_cookie,
        mobile_device=mobile_device or getattr(user, 'authenticated_mobile_device', None)
    )

    if related_objs:
        token.related_objects.add(*related_objs)
    if token.is_authenticated:
        if hasattr(request, 'user'):
            request.user = user
        user_logged_in.send(sender=user.__class__, request=request, user=user)
    request.token = token
    rotate_token(request)


def authorize_login(authorization_token, request=None):
    """
    Set authorization token to be fully authenticated.
    Args:
        request: django HTTP request.
        authorization_token: authorization token to be authenticated
    """
    if not authorization_token.is_authenticated:
        authorization_token.change_and_save(is_authenticated=True, update_only_changed_fields=True)
        user_logged_in.send(sender=authorization_token.user.__class__, request=request, user=authorization_token.user)
        if request and authorization_token == request.token:
            request.token = authorization_token
            request.user = get_user_from_token(authorization_token)


def logout(request):
    """
    Set current token as an inactive.
    Args:
        request: Django HTTP request instance.
    """
    from auth_token.models import AnonymousAuthorizationToken

    # Dispatch the signal before the user is logged out so the receivers have a
    # chance to find out *who* logged out.
    user = getattr(request, 'user', None)
    if hasattr(user, 'is_authenticated') and not user.is_authenticated:
        user = None
    user_logged_out.send(sender=user.__class__, request=request, user=user)

    if hasattr(request, 'token') and request.token.is_active:
        if request.token.active_takeover:
            request.token.active_takeover.change_and_save(is_active=False)
            if hasattr(request, 'user'):
                request.user = request.token.user
        else:
            token = request.token
            token.change_and_save(is_active=False)
            request.token = AnonymousAuthorizationToken()

    if hasattr(request, 'session'):
        request.session.flush()
    if hasattr(request, 'user'):
        request.user = AnonymousUser()


def create_auth_header_value(token):
    """
    Create value for HTTP header.
    Args:
        token: authorization token key. (ex. 123456)

    Returns:
        HTTP header value (ex. Bearer 123456)
    """
    return token if settings.HEADER_TOKEN_TYPE is None else '{} {}'.format(settings.HEADER_TOKEN_TYPE, token)


def parse_auth_header_value(request):
    """
    Parse a token parsed from the "Authorization" header.
    Args:
        request: Django HTTP request instance.

    Returns:
        authorization token key.
    """
    header_value = request.META.get(header_name_to_django(settings.HEADER_NAME))

    if not header_value:
        raise ValueError('Authorization header missing')

    if settings.HEADER_TOKEN_TYPE is None:
        return header_value
    else:
        match = re.match(
            '{} ([^ ]+)$'.format(settings.HEADER_TOKEN_TYPE),
            request.META.get(header_name_to_django(settings.HEADER_NAME), '')
        )
    return match.group(1) if match else None


def get_token_key_from_request(request):
    """
    Return authorization token key from Django request instance.
    Args:
        request: Django HTTP request instance.

    Returns:
        tuple with values (token key, boolean if request was get from header, boolean if request was get from cookie)
    """
    if settings.HEADER and header_name_to_django(settings.HEADER_NAME) in request.META:
        return parse_auth_header_value(request), True, False
    elif settings.COOKIE and settings.COOKIE_NAME in request.COOKIES:
        return request.COOKIES.get(settings.COOKIE_NAME), False, True
    else:
        return None, False, False


def get_token(request):
    """
    Returns the token model instance associated with the given request token key.
    If no user is retrieved AnonymousAuthorizationToken is returned.
    Args:
        request: Django HTTP request instance.

    Returns:
        Instance of authorization token.
    """
    from auth_token.models import AnonymousAuthorizationToken, AuthorizationToken, hash_key
    auth_token, token_is_from_header, token_is_from_cookie = get_token_key_from_request(request)

    if auth_token is None:
        return AnonymousAuthorizationToken()

    try:
        token = AuthorizationToken.objects.get(
            key=hash_key(auth_token),
            is_active=True,
            allowed_cookie__gte=token_is_from_cookie,
            allowed_header__gte=token_is_from_header,
            expires_at__gt=now()
        )
        token.is_from_header, token.is_from_cookie = token_is_from_header, token_is_from_cookie
        token.secret_key = auth_token
        return token
    except AuthorizationToken.DoesNotExist:
        return AnonymousAuthorizationToken()


def dont_enforce_csrf_checks(request):
    """
    Check if CSRF validation is required. If token is get from HTTP header CSRF check is not necessary.
    Args:
        request: Django HTTP request instance.

    Returns:
        boolean if csrf check should be processed or none.
    """
    return (
        header_name_to_django(settings.HEADER_NAME) in request.META
        or getattr(request, '_dont_enforce_csrf_checks', False)
    )


def get_user_from_token(token):
    """
    Return user from authorization token.
    Args:
        token: authorization token instance.

    Returns:
        user instance or AnonymousUser.
    """
    if token:
        backend_path = token.backend
        if backend_path in django_settings.AUTHENTICATION_BACKENDS and token.is_authenticated:
            active_takeover_id = token.active_takeover.user_id if token.active_takeover else None
            user_id = token.user_id
            backend = load_backend(backend_path)

            if active_takeover_id:
                return backend.get_user(active_takeover_id)
            else:
                return backend.get_user(user_id) or AnonymousUser()
    return AnonymousUser()


def get_user(request):
    """
    Returns the user model instance associated with the given request token.
    If no user is retrieved an instance of `AnonymousUser` is returned.
    Args:
        request: Django HTTP request instance.

    Returns:
        user instance or AnonymousUser.
    """
    return get_user_from_token(getattr(request, 'token'))


def takeover(request, user):
    """
    Login the current user to any other user.
    Args:
        request: Django HTTP request instance with already authorized user.
        user: takeovered user.

    Returns:
        True if takeover was performed or False.
    """
    if not hasattr(request, 'user') or not request.user.is_authenticated or request.user == user:
        return False
    else:
        request.token.user_takeovers.update(is_active=False)
        request.token.user_takeovers.create(user=user, is_active=True)
        return True


def deactivate_otp(slug, key=None, related_objects=None):
    """
    Deactivate one time password with a given slug, key and related objects.
    Args:
        slug: OTP slug
        key: OTP key or None.
        related_objects: list of related objects which must be related with OTP to be deactivated.
    """
    from .models import OneTimePassword

    otp_qs = OneTimePassword.objects.filter(slug=slug, is_active=True)

    if related_objects is not None:
        otp_qs = otp_qs.filter(
            reduce(AND, (
                Q(**{
                    'related_objects__object_id': obj.pk,
                    'related_objects__object_ct': ContentType.objects.get_for_model(obj)
                }) for obj in related_objects
            ))
        )
    if key is not None:
        otp_qs = otp_qs.filter(key=hash_key(key, salt=slug))

    otp_qs.change_and_save(is_active=False)


def create_otp(slug, related_objects=None, data=None, key_generator=None, expiration=None, deactivate_old=False):
    """
    Create new one time password. One time password must be identified with slug.
    Args:
        slug: string for OTP identification.
        related_objects: model instances related with OTP.
        data: data which will be stored with OTP in the JSON format.
        key_generator: OTP key generator.
        expiration: OTP expiration time in seconds, default expiration will be used for None value.
        deactivate_old: deactivate old tokens with the same slug ane related objects.

    Returns:
        OTP instance
    """
    from .models import OneTimePassword, compute_expires_at

    if deactivate_old:
        deactivate_otp(slug, related_objects=related_objects)

    key_generator = settings.OTP_DEFAULT_KEY_GENERATOR if key_generator is None else key_generator
    key_generator = import_string(key_generator) if isinstance(key_generator, str) else key_generator

    otp = OneTimePassword.objects.create(
        slug=slug,
        key_generator=key_generator,
        expires_at=compute_expires_at(expiration or settings.OTP_DEFAULT_AGE),
        data=data
    )
    if related_objects:
        otp.related_objects.add(*related_objects)
    return otp


def get_otp_qs(slug=None, key=None, related_objects=None, **kwargs):
    """
    Return OTP queryset with slug, key or related objects
    Args:
        slug: string for OTP identification.
        key: key used for validation of OTP.
        related_objects: objects related with OTP.
        **kwargs: extra filter kwargs.

    Returns:
        OneTimePassword model queryset
    """
    from .models import OneTimePassword

    otp_qs = OneTimePassword.objects.filter(**kwargs)

    if slug:
        otp_qs = otp_qs.filter(slug=slug)

    if key:
        otp_qs = otp_qs.filter(key=hash_key(key, salt=slug))

    if related_objects is not None:
        otp_qs = otp_qs.filter(
            reduce(AND, (
                Q(**{
                    'related_objects__object_id': obj.pk,
                    'related_objects__object_ct': ContentType.objects.get_for_model(obj)
                }) for obj in related_objects
            ))
        )
    return otp_qs


def get_valid_otp(slug, key=None, related_objects=None, deactivate=False):
    """
    Find and return valid OTP with a given slug and key.
    Args:
        slug: string for OTP identification.
        key: key used for validation of OTP.
        related_objects: list of related objects which must be related with OTP.
        deactivate: deactivate the OTP after successful retrieval.

    Returns:
        valid OTP instance or None value.
    """
    otp = get_otp_qs(
        slug=slug,
        key=key,
        related_objects=related_objects,
        is_active=True,
        expires_at__gt=now()
    ).first('-created_at')

    if otp and deactivate:
        otp.change_and_save(is_active=False)

    return otp


def check_otp(slug, key):
    """
    Check if key is valid for OTP.
    Args:
        slug: string for OTP identification.
        key: key used for validation of OTP.

    Returns:
        True for valid OTP code with a given key, False otherwise.
    """
    return get_valid_otp(slug, key) is not None


def extend_otp(slug, key, expiration=None):
    """
    Extend OTP key with a given expiration time in seconds.
    Args:
        slug: string for OTP identification.
        key: key used for validation of OTP.
        expiration: OTP expiration time in seconds, default expiration will be used for None value.

    Returns:
        True if OTP expiration was extended, False otherwise
    """
    otp = get_valid_otp(slug, key)
    if otp is None:
        return False
    else:
        otp.change_and_save(expires_at=compute_expires_at(expiration or settings.DEFAULT_OTP_AGE))
        return True


def create_authorization_request(slug, user, title, description=None, authorization_token=None,
                                 related_objects=None, data=None, expiration=None, backend_path=None):
    """
    Create authorization request with a given slug, title and description.
    Args:
        slug: string for authorization request identification.
        user: owner of authorization request.
        title: human readable title for a client.
        description: human readable description for a client.
        authorization_token: authorization request can be valid only for specific authorization token.
        related_objects: related model instances which will be stored with authorization request.
        data: extra authorization request data.
        expiration: expiration time in seconds.
        backend_path: path authorization request backend class with authentication implementation.

    Returns:
        new authorization request.
    """
    from .models import AuthorizationRequest

    if not backend_path:
        if len(settings.AUTHORIZATION_REQUEST_BACKENDS) == 1:
            backend_path = settings.AUTHORIZATION_REQUEST_BACKENDS[0]
        else:
            raise ImproperlyConfigured(
                'You must select backend_path if more than one AUTH_TOKEN_AUTHORIZATION_REQUEST_BACKENDS are set'
            )

    backend = get_authorization_backend(backend_path, raise_exception=True)
    expiration = expiration or settings.DEFAULT_AUTHORIZATION_REQUEST_AGE

    authorization_request = AuthorizationRequest.objects.create(
        slug=slug,
        user=user,
        title=title,
        description=description,
        authorization_token=authorization_token,
        data=data,
        expires_at=compute_expires_at(expiration),
        backend=backend_path
    )
    if related_objects:
        authorization_request.related_objects.add(*related_objects)

    backend.initialize(authorization_request)
    return authorization_request


def reset_authorization_request(authorization_request, expiration=None):
    """
    Reset authorization request and increase its expiration.
    Args:
        authorization_request: authorization request where new OTP will be created.
        expiration: expiration time in seconds.

    Returns:
        AuthorizationRequest instance with new authorization data
    """
    assert authorization_request.result is None
    backend = get_authorization_backend(authorization_request.backend, raise_exception=True)
    expiration = expiration or settings.DEFAULT_AUTHORIZATION_REQUEST_AGE

    authorization_request.change_and_save(expires_at=compute_expires_at(expiration))
    backend.initialize(authorization_request)
    return authorization_request


def check_authorization_request(authorization_request, **kwargs):
    """
    Check if data send by client is valid with autorization request and access can be granted.
    Args:
        authorization_request: validated authorization request
        **kwargs: data used for request authentication.

    Returns:
        True for valid input data, False otherwise.
    """
    if authorization_request.state != AuthorizationRequestState.WAITING:
        return False

    backend = get_authorization_backend(authorization_request.backend, raise_exception=False)

    if not backend:
        return False
    return backend.authenticate(authorization_request, **kwargs)


def grant_authorization_request(authorization_request, **kwargs):
    """
    Grant access for the authorization request.
    Args:
        authorization_request: authorization request to grant.
        **kwargs: extra data which will be send to the signal.
    """
    assert authorization_request.result is None

    backend = get_authorization_backend(authorization_request.backend, raise_exception=False)
    if backend:
        backend.grant(authorization_request)
    authorization_request.change_and_save(
        result=AuthorizationRequestResult.GRANTED,
        granted_at=now()
    )
    authorization_granted.send(sender=authorization_request.slug, authorization_request=authorization_request, **kwargs)


def deny_authorization_request(authorization_request, **kwargs):
    """
    Deny access for the authorization request.
    Args:
       authorization_request: authorization request to deny.
       **kwargs: extra data which will be send to the signal.
    """
    assert authorization_request.result is None

    backend = get_authorization_backend(authorization_request.backend, raise_exception=False)
    if backend:
        backend.deny(authorization_request)
    authorization_request.change_and_save(result=AuthorizationRequestResult.DENIED)
    authorization_denied.send(sender=authorization_request.slug, authorization_request=authorization_request)


def cancel_authorization_request(authorization_request, **kwargs):
    """
    Cancel authorization request.
    Args:
        authorization_request: authorization request to cancel.
        **kwargs: extra data which will be send to the signal.
    """
    assert authorization_request.result is None

    backend = get_authorization_backend(authorization_request.backend, raise_exception=False)
    if backend:
        backend.cancel(authorization_request)
    authorization_request.change_and_save(result=AuthorizationRequestResult.CANCELLED)
    authorization_cancelled.send(sender=authorization_request.slug, authorization_request=authorization_request)
