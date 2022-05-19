import re
import string

from datetime import timedelta

from unittest import mock

from freezegun import freeze_time

from django.core.management import call_command
from django.utils.timezone import now
from django.test import override_settings
from django.test.client import RequestFactory

from germanium.decorators import data_consumer
from germanium.test_cases.default import GermaniumTestCase
from germanium.tools import (
    assert_equal, assert_true, assert_raises, assert_false, assert_not_raises, assert_not_equal, assert_is_none,
    assert_is_instance, assert_is_not_none
)

from auth_token.enums import AuthorizationRequestState
from auth_token.exceptions import KeyGeneratorError
from auth_token.models import AnonymousUser, AnonymousAuthorizationToken, MobileDevice
from auth_token.utils import (
    compute_expires_at, hash_key, header_name_to_django, generate_key,
    create_auth_header_value, login, logout, parse_auth_header_value, get_token_key_from_request,
    get_token, dont_enforce_csrf_checks, get_user_from_token, get_user, takeover, create_otp, deactivate_otp,
    get_valid_otp, check_otp, extend_otp, create_authorization_request, check_authorization_request,
    grant_authorization_request, deny_authorization_request,cancel_authorization_request, reset_authorization_request,
    get_otp_qs, generate_otp_key
)
from auth_token.signals import authorization_granted, authorization_denied, authorization_cancelled
from auth_token.authorization_request.backends import default_otp_authorization_request_generator

from .base import BaseTestCaseMixin


__all__ = (
   'UtilsTestCase',
)


def authorization_receiver(sender, authorization_request, **kwargs):
    pass


def test_otp_generator():
    return '12345'


def auth_token_age_test(request, user, auth_token):
    return 1234


class UtilsTestCase(BaseTestCaseMixin, GermaniumTestCase):

    def set_up(self):
        # Every test needs access to the request factory.
        self.requiest_factory = RequestFactory()

    @freeze_time(now())
    def test_compute_expires_at_should_return_valid_value(self):
        assert_equal(compute_expires_at(61), now() + timedelta(seconds=61))
        assert_equal(compute_expires_at(126), now() + timedelta(seconds=126))

    test_hash_data = (
        ('1234', '', '2accd14793919bb56639d6e90992378bd5dcb1384082a0822f851aff73587c14'),
        ('secret', '', '829dd60c4cb2c9acd3068bb6f42af56047a0c677067dcf55e26bc7755d7f193c'),
        ('secret', None, '829dd60c4cb2c9acd3068bb6f42af56047a0c677067dcf55e26bc7755d7f193c'),
        ('secret', 'salt', '8ed3095217b32faeafbb2b85463c7de48827df6219a4eaaf4268e4220f6085a9'),
    )

    @data_consumer(test_hash_data)
    def test_hash_key_should_return_valid_value(self, key, salt, key_hash):
        assert_equal(hash_key(key, salt=salt), key_hash)

    test_header_names_data = (
        ('X-Auth', 'HTTP_X_AUTH'),
        ('X-AUTH', 'HTTP_X_AUTH'),
        ('x-auth', 'HTTP_X_AUTH'),
    )

    @data_consumer(test_header_names_data)
    def test_header_name_to_django_should_return_valid_value(self, header_name, django_header_name):
        assert_equal(header_name_to_django(header_name), django_header_name)

    def test_generate_key_should_generate_random_keys(self):
        assert_equal(generate_key(characters='a'), 20 * 'a')
        assert_equal(generate_key(characters='a', length=10), 10 * 'a')
        assert_equal(len(generate_key(length=10)), 10)
        assert_true(set(generate_key(characters='ab')) <= {'a', 'b'})

    def test_create_auth_header_value_should_return_value_with_bearer_prefix(self):
        assert_equal(create_auth_header_value('token'), 'Bearer token')

    @data_consumer('create_user')
    def test_login_user_should_require_select_backend(self, user):
        request = self.requiest_factory.get('/login/')
        with assert_raises(ValueError):
            login(request, user)

    @freeze_time(now())
    @data_consumer('create_user')
    def test_login_user_should_create_authorization_token(self, user):
        request = self.requiest_factory.get('/login/')
        login(request, user, backend='LoginBackend')
        authorization_token = request.token
        assert_equal(authorization_token.user, user)
        assert_true(authorization_token.is_authenticated)
        assert_equal(authorization_token.ip, '127.0.0.1')
        assert_equal(authorization_token.expires_at, now() + timedelta(hours=1))
        assert_equal(authorization_token.backend, 'LoginBackend')
        assert_true(authorization_token.allowed_cookie)
        assert_true(authorization_token.allowed_header)

    @freeze_time(now())
    @data_consumer('create_user')
    def test_login_user_with_two_factor_should_create_unauthenticated_authorization(self, user):
        request = self.requiest_factory.get('/login/')
        login(request, user, backend='LoginBackend', two_factor_login=True)
        assert_false(request.token.is_authenticated)

    @freeze_time(now())
    @data_consumer('create_user')
    def test_login_user_with_no_default_values_should_create_authorization(self, user):
        request = self.requiest_factory.get('/login/')
        login(request, user, backend='LoginBackend', two_factor_login=True, allowed_cookie=False,
              allowed_header=False, expiration=1, auth_slug='test', related_objs=[user])
        authorization_token = request.token
        assert_false(authorization_token.is_authenticated)
        assert_equal(authorization_token.ip, '127.0.0.1')
        assert_equal(authorization_token.expires_at, now() + timedelta(seconds=1))
        assert_equal(authorization_token.backend, 'LoginBackend')
        assert_false(authorization_token.allowed_cookie)
        assert_false(authorization_token.allowed_header)
        assert_true(authorization_token.related_objects.count(), 1)
        assert_equal(authorization_token.related_objects.get().object, user)

    def test_logout_without_user_should_not_raise_exception(self):
        with assert_not_raises(Exception):
            request = self.requiest_factory.get('/logout/')
            logout(request)

    @data_consumer('create_user')
    def test_logout_with_user_without_token_should_logout_it(self, user):
        request = self.requiest_factory.get('/logout/')
        request.user = user
        logout(request)
        assert_false(request.user.is_authenticated)
        assert_not_equal(request.user, user)

    @data_consumer('create_user')
    def test_logout_with_user_with_token_should_logout_it(self, user):
        request = self.requiest_factory.get('/logout/')
        request.user = None
        login(request, user, backend='LoginBackend')
        assert_true(request.user.is_authenticated)
        assert_true(request.token.is_authenticated)
        logout(request)
        assert_false(request.user.is_authenticated)
        assert_false(request.token.is_authenticated)

    def test_parse_auth_header_value_should_return_token(self):
        request = self.requiest_factory.get('/')
        request.META['HTTP_AUTHORIZATION'] = 'Bearer TOKEN'
        assert_equal(parse_auth_header_value(request), 'TOKEN')

    def test_parse_auth_header_missing_value_should_raise_exception(self):
        request = self.requiest_factory.get('/')
        with assert_raises(ValueError):
            parse_auth_header_value(request)

    def test_parse_auth_header_invalid_value_should_return_none(self):
        request = self.requiest_factory.get('/')
        request.META['HTTP_AUTHORIZATION'] = 'Invalid TOKEN'
        assert_is_none(parse_auth_header_value(request))

    def test_get_token_key_from_request_should_be_returned_from_header(self):
        request = self.requiest_factory.get('/')
        request.META['HTTP_AUTHORIZATION'] = 'Bearer TOKEN'
        assert_equal(get_token_key_from_request(request), ('TOKEN', True, False))

    def test_get_token_key_from_request_should_be_returned_from_cookie(self):
        request = self.requiest_factory.get('/')
        request.COOKIES['Authorization'] = 'TOKEN'
        assert_equal(get_token_key_from_request(request), ('TOKEN', False, True))

    def test_get_token_key_from_request_should_return_no_token(self):
        request = self.requiest_factory.get('/')
        assert_equal(get_token_key_from_request(request), (None, False, False))

    @data_consumer('create_user')
    def test_get_token_should_return_token_from_request_header(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        token = request.token
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(token.secret_key)
        assert_equal(get_token(request), token)

    @data_consumer('create_user')
    def test_get_token_should_return_token_from_request_cookie(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        token = request.token
        request.COOKIES['Authorization'] = token.secret_key
        assert_equal(get_token(request), token)

    @data_consumer('create_user')
    def test_get_token_should_not_return_token_from_header_if_secret_is_invalid(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        request.META['HTTP_AUTHORIZATION'] = 'Bearer invalid'
        assert_false(get_token(request).is_active)
        assert_not_equal(get_token(request), request.token)

    @data_consumer('create_user')
    def test_get_token_should_not_return_token_from_cookie_if_secret_is_invalid(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        request.COOKIES['Authorization'] = 'invalid'
        assert_false(get_token(request).is_active)
        assert_not_equal(get_token(request), request.token)

    @data_consumer('create_user')
    def test_get_token_should_not_return_token_without_authorization_data_in_request(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        assert_false(get_token(request).is_active)
        assert_not_equal(get_token(request), request.token)

    @data_consumer('create_user')
    def test_get_token_should_not_return_token_from_request_cookie_if_cookie_is_not_allowed(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend', allowed_cookie=False)
        token = request.token
        request.COOKIES['Authorization'] = token.secret_key
        assert_false(get_token(request).is_active)
        assert_not_equal(get_token(request), request.token)

    @data_consumer('create_user')
    def test_get_token_should_not_return_token_from_request_header_if_header_is_not_allowed(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend', allowed_header=False)
        token = request.token
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(token.secret_key)
        assert_false(get_token(request).is_active)
        assert_not_equal(get_token(request), request.token)

    @data_consumer('create_user')
    def test_get_token_should_not_return_token_from_request_header_if_token_is_expired(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        token = request.token
        token.change_and_save(expires_at=now())
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(token.secret_key)
        assert_false(get_token(request).is_active)
        assert_not_equal(get_token(request), request.token)

    def test_dont_enforce_csrf_checks_should_return_false_for_no_token(self):
        request = self.requiest_factory.get('/')
        assert_false(dont_enforce_csrf_checks(request))

    @data_consumer('create_user')
    def test_dont_enforce_csrf_checks_should_return_true_for_token_from_header(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        token = request.token
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(token.secret_key)
        assert_true(dont_enforce_csrf_checks(request))

    def test_dont_enforce_csrf_checks_should_return_true_for_request_with_flag(self):
        request = self.requiest_factory.get('/')
        request._dont_enforce_csrf_checks = True
        assert_true(dont_enforce_csrf_checks(request))

    def test_get_user_from_token_should_return_anonymous_user_for_no_token_or_anonymous_token(self):
        assert_is_instance(get_user_from_token(None), AnonymousUser)
        assert_is_instance(get_user_from_token(AnonymousAuthorizationToken()), AnonymousUser)

    @data_consumer('create_user')
    def test_get_user_from_token_should_return_anonymous_user_for_token_with_invalid_backend(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='LoginBackend')
        token = request.token
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(token.secret_key)
        assert_is_instance(get_user_from_token(token), AnonymousUser)

    @data_consumer('create_user')
    def test_get_user_from_token_should_return_user_for_valid_token(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='auth_token.backends.DeviceBackend')
        token = request.token
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(token.secret_key)
        assert_equal(get_user_from_token(token), user)

    @data_consumer('create_user')
    def test_get_user_should_return_user_for_valid_token(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='auth_token.backends.DeviceBackend')
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(request.token.secret_key)
        assert_equal(get_user(request), user)

    @data_consumer('create_user')
    def test_takeover_same_user_should_not_create_takeover_instance_and_return_false(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='auth_token.backends.DeviceBackend')
        request.user = user
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(request.token.secret_key)
        assert_false(takeover(request, user))
        assert_equal(request.token.user_takeovers.count(), 0)

    @data_consumer('create_user')
    def test_takeover_user_should_create_takeover_instance_and_return_true(self, user):
        request = self.requiest_factory.get('/')
        login(request, user, backend='auth_token.backends.DeviceBackend')
        request.user = user
        assert_equal(get_user_from_token(request.token), user)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer {}'.format(request.token.secret_key)
        takeovered_user = self.create_user(username='takeovered', email='takeover@test.cz')
        assert_true(takeover(request, takeovered_user))
        assert_equal(request.token.user_takeovers.filter(is_active=True).count(), 1)
        assert_equal(get_user_from_token(request.token), takeovered_user)
        logout(request)
        assert_equal(request.token.user_takeovers.filter(is_active=True).count(), 0)
        assert_equal(get_user_from_token(request.token), user)
        logout(request)
        assert_is_instance(get_user_from_token(request.token), AnonymousUser)

    @freeze_time(now())
    def test_create_otp_should_create_new_otp_instance_with_default_expiration_time(self):
        otp = create_otp('test', key_generator=lambda: '1234')
        assert_equal(otp.slug, 'test')
        assert_equal(otp.expires_at, now() + timedelta(hours=1))
        assert_equal(otp.secret_key, '1234')
        assert_equal(otp.key, hash_key('1234', salt='test'))

    @freeze_time(now())
    def test_create_otp_should_create_new_otp_instance_with_default_expiration_time(self):
        otp = create_otp('test')
        assert_equal(otp.slug, 'test')
        assert_equal(otp.expires_at, now() + timedelta(hours=1))
        assert_equal(otp.key, hash_key(otp.secret_key, salt='test'))

    @freeze_time(now())
    @data_consumer('create_user')
    def test_create_otp_should_create_new_otp_with_custom_key_generator_and_expiration(self, user):
        otp = create_otp('test', key_generator=lambda: '1234', expiration=14, related_objects=[user],
                         data={'otp': 'data'})
        assert_equal(otp.slug, 'test')
        assert_equal(otp.expires_at, now() + timedelta(seconds=14))
        assert_equal(otp.secret_key, '1234')
        assert_equal(otp.key, hash_key('1234', salt='test'))
        assert_equal(otp.data, {'otp': 'data'})
        assert_equal(otp.related_objects.count(), 1)
        assert_equal(otp.related_objects.get().object, user)

    @freeze_time(now())
    @override_settings(AUTH_TOKEN_OTP_DEFAULT_KEY_GENERATOR='app.tests.utils.test_otp_generator')
    @data_consumer('create_user')
    def test_create_otp_should_create_new_otp_with_changed_default_generator_in_config(self, user):
        otp = create_otp('test')
        assert_equal(otp.secret_key, '12345')
        assert_equal(otp.key, hash_key('12345', salt='test'))

    def test_create_otp_with_deactivation_old_otp_codes_should_deactivate_it(self):
        otp1 = create_otp('test')
        otp2 = create_otp('test')
        otp3 = create_otp('test2')

        assert_true(otp1.refresh_from_db().is_active)
        assert_true(otp2.refresh_from_db().is_active)
        assert_true(otp3.refresh_from_db().is_active)

        otp4 = create_otp('test', deactivate_old=True)

        assert_false(otp1.refresh_from_db().is_active)
        assert_false(otp2.refresh_from_db().is_active)
        assert_true(otp3.refresh_from_db().is_active)
        assert_true(otp4.refresh_from_db().is_active)

    @data_consumer('create_user')
    def test_deactivate_otp_should_deactivate_otp_according_to_input(self, user):
        otp1 = create_otp('test')
        otp2 = create_otp('test')
        otp3 = create_otp('test', related_objects=[user])
        otp4 = create_otp('test2', related_objects=[user])
        otp5 = create_otp('test')

        deactivate_otp('test', key=otp1.secret_key)
        assert_false(otp1.refresh_from_db().is_active)
        assert_true(otp2.refresh_from_db().is_active)
        assert_true(otp3.refresh_from_db().is_active)
        assert_true(otp4.refresh_from_db().is_active)
        assert_true(otp5.refresh_from_db().is_active)

        deactivate_otp('test', related_objects=[user])
        assert_false(otp1.refresh_from_db().is_active)
        assert_true(otp2.refresh_from_db().is_active)
        assert_false(otp3.refresh_from_db().is_active)
        assert_true(otp4.refresh_from_db().is_active)
        assert_true(otp5.refresh_from_db().is_active)

        deactivate_otp('test')
        assert_false(otp1.refresh_from_db().is_active)
        assert_false(otp2.refresh_from_db().is_active)
        assert_false(otp3.refresh_from_db().is_active)
        assert_true(otp4.refresh_from_db().is_active)
        assert_false(otp5.refresh_from_db().is_active)

    def test_get_valid_otp_should_return_only_valid_otp(self):
        otp1 = create_otp('test')
        otp2 = create_otp('test2')

        assert_is_none(get_valid_otp('test', 'invalid'))
        assert_is_none(get_valid_otp('test2', otp1.secret_key))

        assert_equal(get_valid_otp('test', otp1.secret_key), otp1)
        assert_equal(get_valid_otp('test2', otp2.secret_key), otp2)

        deactivate_otp('test')
        assert_is_none(get_valid_otp('test', otp1.secret_key))

    def test_get_valid_otp_should_return_last_valid_otp(self):
        otp1 = create_otp('test')
        otp2 = create_otp('test')

        assert_equal(get_valid_otp('test', otp1.secret_key), otp1)
        assert_equal(get_valid_otp('test', otp2.secret_key), otp2)
        assert_equal(get_valid_otp('test'), otp2)

    @data_consumer('create_user')
    def test_get_valid_otp_should_return_otp_according_to_related_objects(self, user):
        otp1 = create_otp('test', related_objects=[user])
        otp2 = create_otp('test')

        assert_equal(get_valid_otp('test', otp1.secret_key), otp1)
        assert_equal(get_valid_otp('test', otp2.secret_key), otp2)
        assert_equal(get_valid_otp('test'), otp2)
        assert_equal(get_valid_otp('test', related_objects=[user]), otp1)
        assert_is_none(get_valid_otp('test', otp2.secret_key, related_objects=[user]))

    def test_get_valid_otp_should_deactive_returned_otp(self):
        otp = create_otp('test')
        get_valid_otp('test', otp.secret_key, deactivate=True)
        assert_false(otp.refresh_from_db().is_active)

    def test_check_otp_should_return_true_if_input_data_are_valid(self):
        otp1 = create_otp('test')
        otp2 = create_otp('test2')

        assert_false(check_otp('test', 'invalid'))
        assert_false(check_otp('test2', otp1.secret_key))

        assert_true(check_otp('test', otp1.secret_key))
        assert_true(check_otp('test2', otp2.secret_key))

        deactivate_otp('test')
        assert_false(check_otp('test', otp1.secret_key))

    @freeze_time(now())
    def test_extend_otp_should_extend_otp_expiration(self):
        otp = create_otp('test', expiration=1)
        assert_equal(otp.expires_at, now() + timedelta(seconds=1))

        assert_true(extend_otp('test', otp.secret_key, expiration=5))
        assert_equal(otp.refresh_from_db().expires_at, now() + timedelta(seconds=5))

        assert_true(extend_otp('test', otp.secret_key, expiration=3600))
        assert_equal(otp.refresh_from_db().expires_at, now() + timedelta(hours=1))

        assert_false(extend_otp('test2', otp.secret_key, expiration=3611))
        assert_equal(otp.refresh_from_db().expires_at, now() + timedelta(hours=1))

        assert_false(extend_otp('test', 'invalid', expiration=3611))
        assert_equal(otp.refresh_from_db().expires_at, now() + timedelta(hours=1))

        deactivate_otp('test')
        assert_false(extend_otp('test', otp.secret_key, expiration=3611))
        assert_equal(otp.refresh_from_db().expires_at, now() + timedelta(hours=1))

    @freeze_time(now())
    @data_consumer('create_user')
    @override_settings(AUTH_TOKEN_AUTHORIZATION_REQUEST_BACKENDS=[
        'auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'])
    def test_create_authorization_request_should_create_new_authorization_with_otp(self, user):
        authorization_request = create_authorization_request('test', user, 'test')
        assert_equal(authorization_request.slug, 'test')
        assert_equal(authorization_request.title, 'test')
        assert_is_none(authorization_request.description)
        assert_equal(get_otp_qs(related_objects=[authorization_request], is_active=True).count(), 1)
        assert_equal(authorization_request.expires_at, now() + timedelta(hours=1))

    @freeze_time(now())
    @data_consumer('create_user')
    def test_create_authorization_request_should_create_new_authorization_with_no_default_values(self, user):
        authorization_request = create_authorization_request(
            'slug', user, 'title', description='description', related_objects=[user],
            data={'authorization': 'data'},  expiration=1,
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.slug, 'slug')
        assert_equal(authorization_request.user, user)
        assert_equal(authorization_request.title, 'title')
        assert_equal(authorization_request.description, 'description')
        assert_equal(authorization_request.related_objects.count(), 1)
        assert_equal(authorization_request.related_objects.get().object, user)
        assert_equal(
            get_valid_otp(authorization_request.slug, related_objects=[authorization_request]).expires_at,
            now() + timedelta(seconds=1)
        )
        assert_equal(authorization_request.expires_at, now() + timedelta(seconds=1))

    @data_consumer('create_user')
    def test_create_authorization_request_with_device_type_should_create_it(self, user):
        authorization_request = create_authorization_request(
            'slug', user, 'title',
            backend_path='auth_token.authorization_request.backends.MobileDeviceAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.slug, 'slug')
        assert_equal(authorization_request.title, 'title')

    @data_consumer('create_user')
    def test_check_authorization_request_with_mobile_device_type_should_return_right_value(self, user):
        mobile_device_login_token = MobileDevice.objects.activate_or_create(
            uuid='E621E1F8C36C495', user=user
        ).secret_password
        authorization_request = create_authorization_request(
            'slug', user, 'title',
            backend_path='auth_token.authorization_request.backends.MobileDeviceAuthorizationRequestBackend'
        )

        assert_false(check_authorization_request(authorization_request))
        assert_false(check_authorization_request(authorization_request, mobile_device_uuid='E621E1F8C36C495'))
        assert_true(check_authorization_request(authorization_request, mobile_device_uuid='E621E1F8C36C495',
                                                mobile_login_token=mobile_device_login_token))

    @data_consumer('create_user')
    def test_check_authorization_request_with_mobile_device_type_and_token_should_return_right_value(self, user):
        mobile_device = MobileDevice.objects.activate_or_create(
            uuid='E621E1F8C36C495', user=user
        )
        authorization_request = create_authorization_request(
            'slug', user, 'title',
            backend_path='auth_token.authorization_request.backends.MobileDeviceAuthorizationRequestBackend'
        )
        assert_true(check_authorization_request(authorization_request, mobile_device_uuid='E621E1F8C36C495',
                                                mobile_login_token=mobile_device.secret_password))

    @freeze_time(now())
    @data_consumer('create_user')
    def test_check_authorization_request_with_otp_should_return_right_value(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )

        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        assert_false(check_authorization_request(authorization_request))
        assert_false(check_authorization_request(authorization_request, otp_secret_key='invalid'))
        assert_true(check_authorization_request(authorization_request,
                                                otp_secret_key=authorization_request.secret_key))
        with override_settings(AUTH_TOKEN_AUTHORIZATION_REQUEST_OTP_DEBUG_CODE='invalid'):
            assert_true(check_authorization_request(authorization_request, otp_secret_key='invalid'))

        with freeze_time(now() + timedelta(hours=1, seconds=1)):
            # Expired authorization
            assert_false(check_authorization_request(authorization_request,
                                                     otp_secret_key=authorization_request.secret_key))
            assert_equal(authorization_request.state, AuthorizationRequestState.EXPIRED)

    @freeze_time(now())
    @data_consumer('create_user')
    def test_authorization_reset_create_new_otp_key_and_increase_expiration(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(get_otp_qs(related_objects=[authorization_request]).count(), 1)
        assert_equal(authorization_request.expires_at, now() + timedelta(hours=1))

        secret_key = authorization_request.secret_key
        assert_true(check_authorization_request(authorization_request, otp_secret_key=secret_key))

        with freeze_time(now() + timedelta(minutes=5)):
            authorization_request = reset_authorization_request(authorization_request)
            assert_equal(authorization_request.expires_at, now() + timedelta(hours=1))
            assert_equal(get_otp_qs(related_objects=[authorization_request]).count(), 2)
            assert_equal(get_otp_qs(related_objects=[authorization_request], is_active=True).count(), 1)
            assert_false(check_authorization_request(authorization_request, otp_secret_key=secret_key))
            assert_true(check_authorization_request(authorization_request,
                                                    otp_secret_key=authorization_request.secret_key))

            authorization_request = reset_authorization_request(authorization_request, expiration=5)
            assert_equal(authorization_request.expires_at, now() + timedelta(seconds=5))

    @data_consumer('create_user')
    def test_grant_authorization_request_should_grant_authorization_and_call_receiver(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        with mock.patch('dj.apps.app.tests.utils.authorization_receiver') as mocked_receiver:
            authorization_granted.connect(mocked_receiver, sender='test')
            grant_authorization_request(authorization_request, extra_data='test')
            mocked_receiver.assert_called()
            assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.GRANTED)

    @data_consumer('create_user')
    def test_grant_authorization_request_should_grant_authorization_and_not_call_receiver_with_another_slug(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        with mock.patch('dj.apps.app.tests.utils.authorization_receiver') as mocked_receiver:
            authorization_granted.connect(mocked_receiver, sender='test2')
            grant_authorization_request(authorization_request)
            mocked_receiver.assert_not_called()
            authorization_request.refresh_from_db()
            assert_equal(authorization_request.state, AuthorizationRequestState.GRANTED)
            assert_is_not_none(authorization_request.granted_at)

    @data_consumer('create_user')
    def test_grant_authorization_request_should_not_grant_already_granted_authorization(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        grant_authorization_request(authorization_request)
        assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.GRANTED)
        with assert_raises(AssertionError):
            grant_authorization_request(authorization_request)

    @data_consumer('create_user')
    def test_deny_authorization_request_should_not_deny_already_granted_authorization(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        grant_authorization_request(authorization_request)
        assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.GRANTED)
        with assert_raises(AssertionError):
            deny_authorization_request(authorization_request)

    @data_consumer('create_user')
    def test_deny_authorization_request_should_deny_authorization_and_call_receiver(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        with mock.patch('dj.apps.app.tests.utils.authorization_receiver') as mocked_receiver:
            authorization_denied.connect(mocked_receiver, sender='test')
            deny_authorization_request(authorization_request)
            mocked_receiver.assert_called()
            assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.DENIED)

    @data_consumer('create_user')
    def test_deny_authorization_request_should_deny_authorization_and_not_call_receiver_with_another_slug(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        with mock.patch('dj.apps.app.tests.utils.authorization_receiver') as mocked_receiver:
            authorization_denied.connect(mocked_receiver, sender='test2')
            deny_authorization_request(authorization_request)
            mocked_receiver.assert_not_called()
            assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.DENIED)

    @data_consumer('create_user')
    def test_cancel_authorization_request_should_not_cancel_already_granted_authorization(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        grant_authorization_request(authorization_request)
        assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.GRANTED)
        with assert_raises(AssertionError):
            cancel_authorization_request(authorization_request)

    @data_consumer('create_user')
    def test_cancel_authorization_request_should_deny_authorization_and_call_receiver(self, user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        with mock.patch('dj.apps.app.tests.utils.authorization_receiver') as mocked_receiver:
            authorization_cancelled.connect(mocked_receiver, sender='test')
            cancel_authorization_request(authorization_request)
            mocked_receiver.assert_called()
            assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.CANCELLED)

    @data_consumer('create_user')
    def test_cancel_authorization_request_should_cancel_authorization_and_not_call_receiver_with_another_slug(self,
                                                                                                              user):
        authorization_request = create_authorization_request(
            'test', user, 'test',
            backend_path='auth_token.authorization_request.backends.OTPAuthorizationRequestBackend'
        )
        assert_equal(authorization_request.state, AuthorizationRequestState.WAITING)
        with mock.patch('dj.apps.app.tests.utils.authorization_receiver') as mocked_receiver:
            authorization_cancelled.connect(mocked_receiver, sender='test2')
            cancel_authorization_request(authorization_request)
            mocked_receiver.assert_not_called()
            assert_equal(authorization_request.refresh_from_db().state, AuthorizationRequestState.CANCELLED)

    @freeze_time(now())
    def test_duplicite_key_generator_should_raise_exception(self):
        create_otp('test', key_generator=lambda: '1234')
        with assert_raises(KeyGeneratorError):
            create_otp('test', key_generator=lambda: '1234')

    @freeze_time(now())
    def test_key_genrator_should_be_called_more_times(self):
        def key_genertor():
            key_genertor.iteration += 1
            if key_genertor.iteration < 100:
                return '1234'
            else:
                return '1235'
        key_genertor.iteration = 0

        create_otp('test', key_generator=lambda: '1234')
        assert_equal(create_otp('test', key_generator=key_genertor).secret_key, '1235')
        assert_equal(key_genertor.iteration, 100)

    def test_generate_otp_key_should_generate_20_chars_length_key(self):
        for _ in range(20):
            assert_true(re.match(r'^[a-zA-Z0-9]{20}$', generate_otp_key()))

    def test_default_otp_authorization_request_generator_should_generate_6_length_digit_key(self):
        for _ in range(20):
            assert_true(re.match(r'^[0-9]{6}$', default_otp_authorization_request_generator()))

    @data_consumer('create_user')
    @override_settings(AUTH_TOKEN_AGE_CALLBACK='app.tests.utils.auth_token_age_test')
    def test_get_auth_token_age_should_return_(self, user):
        with freeze_time():
            request = self.requiest_factory.get('/')
            login(request, user, backend='LoginBackend', allowed_cookie=False)
            token = request.token
            assert_equal(token.expires_at, now() + timedelta(seconds=1234))
