from datetime import timedelta

from django.conf import settings as django_settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AnonymousUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.utils import IntegrityError
from django.utils import timezone
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy as _l

from auth_token.config import settings
from auth_token.utils import generate_key


class Token(models.Model):
    """
    The default authorization token model.
    """

    key = models.CharField(max_length=40, primary_key=True, null=False, blank=False)
    user = models.ForeignKey(django_settings.AUTH_USER_MODEL, related_name='auth_token', null=False, blank=False,
                             on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, null=False, blank=False)
    last_access = models.DateTimeField(auto_now=True, null=False, blank=False)
    is_active = models.BooleanField(default=True)
    # It is possiple use https://github.com/selwin/django-user_agents/tree/master/django_user_agents or
    # https://github.com/selwin/python-user-agents for parse
    # Limited size to 256
    user_agent = models.CharField(max_length=256, null=True, blank=True)
    expiration = models.BooleanField(default=True)
    ip = models.GenericIPAddressField(null=False, blank=False)
    auth_slug = models.SlugField(null=True, blank=True)
    backend = models.CharField(max_length=255, null=False, blank=False)
    allowed_cookie = models.BooleanField(default=True)
    allowed_header = models.BooleanField(default=True)

    is_from_header = False
    is_from_cookie = False

    @property
    def active_takeover(self):
        return self.user_takeovers.filter(is_active=True).last()

    def save(self, *args, **kwargs):
        if not self.key:
             self.key = self._generate_unique_key()
        return super().save(*args, **kwargs)

    def _generate_unique_key(self):
        """
        Generate random unique token key.
        """
        key = generate_key()
        try_generator_iterations = 1
        while self.__class__.objects.filter(key=key).exists():
            if try_generator_iterations > settings.MAX_RANDOM_KEY_ITERATIONS:
                raise IntegrityError('Could not produce unique key for authorization token')
            try_generator_iterations += 1
            key = generate_key()
        return key

    def _get_token_age(self):
        return self.expiration and settings.DEFAULT_TOKEN_AGE or settings.MAX_TOKEN_AGE

    @property
    def is_expired(self):
        return self.last_access + timedelta(seconds=self._get_token_age()) < timezone.now()

    @property
    def time_to_expiration(self):
        return (self.last_access + timedelta(seconds=self._get_token_age())) - timezone.now()

    @property
    def str_time_to_expiration(self):
        return str(self.time_to_expiration) if self.time_to_expiration.total_seconds() > 0 else '00:00:00'

    def __str__(self):
        return self.key


class TokenRelatedObject(models.Model):
    """
    Generic relation to objects related with authorization token
    """

    token = models.ForeignKey(Token, related_name='related_objects', on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.TextField()
    content_object = GenericForeignKey('content_type', 'object_id')


class UserTokenTakeover(models.Model):
    """
    The model allows to change user without token change
    """

    token = models.ForeignKey(Token, related_name='user_takeovers', on_delete=models.CASCADE)
    user = models.ForeignKey(django_settings.AUTH_USER_MODEL, related_name='user_token_takeovers', null=False,
                             blank=False, on_delete=models.CASCADE)
    is_active = models.BooleanField()


class AnonymousToken:

    key = None
    user = AnonymousUser
    creted_at = None
    is_active = False
    user_agent = None
    is_expired = True
    is_from_header = False
    is_from_cookie = False
    active_takeover = None
    backend = None
    allowed_cookie = False
    allowed_header = False

    def save(self):
        raise NotImplementedError

    def delete(self):
        raise NotImplementedError


class DeviceKeyQuerySet(models.QuerySet):

    def get_or_create_token(self, uuid, user, user_agent=''):
        """
        This method must be called when user is authenticated.
        It creates a new DeviceKey for the device and returns it.
        If DeviceKey for the same UUID, device ID
        and user already exists then it remain as it is and None is returned.
        """
        token = generate_key(length=64)
        return token, self.get_or_create(
            uuid=uuid, is_active=True, user=user,
            defaults={
                'login_token': make_password(token),
                'user_agent': user_agent[:256],
            }
        )[1]


class DeviceKey(models.Model):
    """Model used to authenticate mobile devices. Unhashed login_token is stored
    in the device keychain and serve as password to log in together with UUID via DeviceBackend."""

    created_at = models.DateTimeField(auto_now_add=True, null=False, blank=False, verbose_name=_('created at'))
    # this is not UUIDField because of the strict length limitation
    uuid = models.CharField(unique=True, verbose_name=_('UUID'), max_length=32)
    last_login = models.DateTimeField(null=True, blank=True, verbose_name=_('last login'))
    user = models.ForeignKey(django_settings.AUTH_USER_MODEL, on_delete=models.CASCADE, verbose_name=_('user'))
    login_token = models.CharField(max_length=128, verbose_name=_('login token'))
    is_active = models.BooleanField(default=True, verbose_name=_('is active'))
    user_agent = models.CharField(max_length=256, null=True, blank=True, verbose_name=_('user agent'))

    class Meta:
        unique_together = ('uuid', 'user')
        verbose_name = _l('device key')
        verbose_name_plural = _l('device keys')

    objects = DeviceKeyQuerySet.as_manager()

    def __str__(self):
        return '{}, {}'.format(self.uuid, self.user)

    def check_password(self, token):
        return check_password(token, self.login_token)

