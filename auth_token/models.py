from datetime import timedelta

from django.conf import settings as django_settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AnonymousUser
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models, IntegrityError, transaction
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from enumfields import IntegerEnumField

from chamber.exceptions import PersistenceException
from chamber.models import SmartModel, SmartQuerySet, SmartManager

from generic_m2m_field.models import GenericManyToManyField

from auth_token.utils import compute_expires_at, generate_key, hash_key
from auth_token.config import settings

from .enums import AuthorizationRequestState, AuthorizationRequestResult
from .exceptions import KeyGeneratorError


KEY_SALT = 'django-auth-token'


def compute_authorization_token_expires_at(expiration=None):
    return compute_expires_at(expiration or settings.DEFAULT_TOKEN_AGE)


def generate_token_key():
    return generate_key(length=settings.LENGTH)


class BaseHashKeyManager(SmartManager):

    def _hash_key(self, key, **kwargs):
        return hash_key(key)

    def create(self, key_generator, **kwargs):
        for _i in range(settings.MAX_RANDOM_KEY_ITERATIONS):
            try:
                key = key_generator()
                hashed_key = self._hash_key(key, **kwargs)
                obj = super().create(key=hashed_key, **kwargs)
                obj.secret_key = key
                return obj
            except IntegrityError:
                pass
            except PersistenceException as ex:
                if not ex.error_dict and 'key' not in ex.error_dict:
                    raise ex
        raise KeyGeneratorError('Could not produce unique key')


class AuthorizationTokenManager(BaseHashKeyManager):

    def create(self, **kwargs):
        return super().create(generate_token_key, **kwargs)


class AuthorizationToken(SmartModel):
    """
    The default authorization token model.
    """

    key = models.CharField(
        verbose_name=_('key'),
        max_length=128,
        unique=True,
        db_index=True,
        null=False,
        blank=False
    )
    user = models.ForeignKey(
        verbose_name=_('user'),
        to=django_settings.AUTH_USER_MODEL,
        related_name='authorization_tokens',
        null=False,
        blank=False,
        on_delete=models.CASCADE
    )
    is_active = models.BooleanField(
        verbose_name=_('is active'),
        default=True
    )
    user_agent = models.CharField(
        verbose_name=_('user agent'),
        max_length=256,
        null=True,
        blank=True
    )
    expires_at = models.DateTimeField(
        verbose_name=_('expires at'),
        null=False,
        blank=False,
        default=compute_authorization_token_expires_at
    )
    ip = models.GenericIPAddressField(
        verbose_name=_('IP'),
        null=False,
        blank=False
    )
    auth_slug = models.SlugField(
        verbose_name=_('slug'),
        null=True,
        blank=True
    )
    backend = models.CharField(
        verbose_name=_('backend'),
        max_length=250,
        null=False,
        blank=False
    )
    allowed_cookie = models.BooleanField(
        verbose_name=_('is allowed cookie'),
        default=True
    )
    allowed_header = models.BooleanField(
        verbose_name=_('is allowed header'),
        default=True
    )
    is_authenticated = models.BooleanField(
        verbose_name=_('is authenticated'),
        null=False,
        blank=False,
        default=False
    )
    preserve_cookie = models.BooleanField(
        verbose_name=_('preserve cookie'),
        null=False,
        blank=False,
        default=False
    )
    mobile_device = models.ForeignKey(
        verbose_name=_('mobile device'),
        to='MobileDevice',
        related_name='authorization_tokens',
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    related_objects = GenericManyToManyField()

    is_from_header = False
    is_from_cookie = False
    secret_key = None
    is_anonymous = False

    objects = AuthorizationTokenManager()

    class Meta:
        verbose_name = _('authorization token')
        verbose_name_plural = _('authorization tokens')

    class SmartMeta:
        is_cleaned_pre_save = False

    @property
    def active_takeover(self):
        return self.user_takeovers.filter(is_active=True).last()

    @property
    def is_expired(self):
        return self.expires_at < timezone.now()

    @property
    def time_to_expiration(self):
        return max(timedelta(seconds=0), self.expires_at - timezone.now())


class AnonymousAuthorizationToken:

    key = None
    user = AnonymousUser()
    created_at = None
    is_active = False
    user_agent = None
    expiration = None
    is_from_header = False
    is_from_cookie = False
    active_takeover = None
    backend = None
    allowed_cookie = False
    allowed_header = False
    secret_key = None
    is_authenticated = False
    is_anonymous = True

    def save(self):
        raise NotImplementedError

    def delete(self):
        raise NotImplementedError


class UserAuthorizationTokenTakeover(SmartModel):
    """
    The model allows to change user without token change
    """

    token = models.ForeignKey(
        verbose_name=_('authorization token'),
        to=AuthorizationToken,
        related_name='user_takeovers',
        on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        verbose_name=_('user'),
        to=django_settings.AUTH_USER_MODEL,
        related_name='user_token_takeovers',
        null=False,
        blank=False,
        on_delete=models.CASCADE
    )
    is_active = models.BooleanField()

    class Meta:
        verbose_name = _('authorization takeover')
        verbose_name_plural = _('authorization takeovers')


class MobileDeviceAlreadyExists(Exception):
    pass


class MobileDeviceQuerySet(SmartQuerySet):

    def activate_or_create(self, uuid, user, user_agent='', name=None, slug=None, is_primary=True):
        """
        This method must be called when user is authenticated.
        It creates a new MobileDevice with auto generated token for the device and returns token.
        If MobileDevice with same UUID exists MobileDeviceAlreadyExists is raised.
        """
        secret_password = generate_key(length=settings.MOBILE_DEVICE_SECRET_PASSWORD_LENGTH)
        defaults = {
            'login_token': make_password(secret_password),
            'user_agent': user_agent[:256],
            'is_active': True,
            'name': name,
            'slug': slug,
            'is_primary': is_primary
        }
        mobile_device, is_created_mobile_device = self.get_or_create(
            uuid=uuid,
            user=user,
            defaults=defaults
        )
        mobile_device.secret_password = secret_password
        if not is_created_mobile_device and not mobile_device.is_active:
            return mobile_device.change_and_save(**defaults)
        elif is_created_mobile_device:
            return mobile_device
        else:
            raise MobileDeviceAlreadyExists('Device key already exists')


class MobileDevice(SmartModel):
    """Model used to authenticate mobile devices. Unhashed login_token is stored
    in the device keychain and serve as password to log in together with UUID via DeviceBackend."""

    # this is not UUIDField because of the strict length limitation
    uuid = models.CharField(
        verbose_name=_('UUID'),
        max_length=36,
        null=False,
        blank=False
    )
    name = models.CharField(
        verbose_name=_('name'),
        max_length=250,
        null=True,
        blank=True
    )
    slug = models.SlugField(
        verbose_name=_('slug'),
        null=True,
        blank=True
    )
    last_login = models.DateTimeField(
        verbose_name=_('last login'),
        null=True,
        blank=True
    )
    user = models.ForeignKey(
        to=django_settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        verbose_name=_('user'),
        related_name='mobile_devices'
    )
    login_token = models.CharField(
        max_length=128,
        verbose_name=_('login token'),
        null=False,
        blank=False
    )
    is_active = models.BooleanField(
        verbose_name=_('is active'),
        default=True
    )
    user_agent = models.CharField(
        verbose_name=_('user agent'),
        max_length=256,
        null=True,
        blank=True,
    )
    is_primary = models.BooleanField(
        verbose_name=_('is primary'),
        default=False
    )

    class Meta:
        unique_together = ('uuid', 'user')
        verbose_name = _('mobile device')
        verbose_name_plural = _('mobile devices')

    objects = MobileDeviceQuerySet.as_manager()

    @transaction.atomic()
    def _pre_save(self, changed, changed_fields, *args, **kwargs):
        super()._pre_save(self, changed, changed_fields, *args, **kwargs)
        if self.is_primary and 'is_primary' in self.changed_fields:
            # only one device can be primary
            self.__class__.objects.filter(user=self.user).exclude(pk=self.pk).select_for_update().change_and_save(
                is_primary=False
            )

    def check_password(self, token):
        return check_password(str(token), self.login_token)


class OneTimePasswordManager(BaseHashKeyManager):

    def _hash_key(self, key, slug, **kwargs):
        return hash_key(key, salt=slug)

    def create(self, slug, key_generator, **kwargs):
        return super().create(key_generator, slug=slug, **kwargs)


class OneTimePassword(SmartModel):
    """
    Specific verification tokens that can be send via e-mail, SMS or another transmission medium
    to check user authorization (example password reset)
    """

    key = models.CharField(
        verbose_name=_('key'),
        max_length=128,
        unique=True,
        db_index=True,
        null=False,
        blank=False
    )
    expires_at = models.DateTimeField(
        verbose_name=_('expires at'),
        null=True,
        blank=True,
    )
    slug = models.SlugField(
        verbose_name=_('slug'),
        null=False,
        blank=False
    )
    is_active = models.BooleanField(
        verbose_name=_('is active'),
        default=True
    )
    data = models.JSONField(
        verbose_name=_('data'),
        null=True,
        blank=True,
        encoder=DjangoJSONEncoder
    )
    related_objects = GenericManyToManyField()

    secret_key = None

    objects = OneTimePasswordManager()

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _('one time password')
        verbose_name_plural = _('one time passwords')

    @property
    def is_expired(self):
        return self.expires_at and self.expires_at < timezone.now()


class AuthorizationRequest(SmartModel):

    authorization_token = models.ForeignKey(
        verbose_name=_('authorization token'),
        to=AuthorizationToken,
        related_name='authorization_requests',
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    user = models.ForeignKey(
        verbose_name=_('user'),
        to=django_settings.AUTH_USER_MODEL,
        related_name='authorization_requests',
        null=False,
        blank=False,
        on_delete=models.CASCADE
    )
    slug = models.SlugField(
        verbose_name=_('slug'),
        null=True,
        blank=True
    )
    backend = models.CharField(
        verbose_name=_('backend'),
        max_length=250,
        null=False,
        blank=False
    )
    title = models.CharField(
        verbose_name=_('title'),
        max_length=250,
        null=False,
        blank=False
    )
    description = models.TextField(
        verbose_name=_('description'),
        null=True,
        blank=True
    )
    result = IntegerEnumField(
        verbose_name=_('result'),
        enum=AuthorizationRequestResult,
        null=True,
        blank=True
    )
    data = models.JSONField(
        verbose_name=_('data'),
        null=True,
        blank=True,
        encoder=DjangoJSONEncoder
    )
    expires_at = models.DateTimeField(
        verbose_name=_('expires at'),
        null=True,
        blank=True,
    )
    granted_at = models.DateTimeField(
        verbose_name=_('granted at'),
        null=True,
        blank=True
    )
    related_objects = GenericManyToManyField()

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _('authorization request')
        verbose_name_plural = _('authorization requests')

    @property
    def is_expired(self):
        return self.expires_at < timezone.now()

    @property
    def state(self):
        if not self.result and self.is_expired:
            return AuthorizationRequestState.EXPIRED
        elif not self.result:
            return AuthorizationRequestState.WAITING
        else:
            return AuthorizationRequestState[self.result.name]
