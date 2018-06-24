from datetime import timedelta

from django.test import override_settings
from django.utils import timezone

from germanium.annotations import data_provider
from germanium.test_cases.rest import RESTTestCase
from germanium.test_cases.client import ClientTestCase
from germanium.tools.http import assert_http_ok, assert_http_redirect, assert_http_accepted
from germanium.tools import assert_true, assert_false, assert_in, assert_not_in

from freezegun import freeze_time

from auth_token.models import Token

from .base import BaseTestCaseMixin


__all__ = (
   'RESTLoginISCoreTestCase',
   'UILoginISCoreTestCase',
)


class RESTLoginISCoreTestCase(BaseTestCaseMixin, RESTTestCase):

    INDEX_URL = '/is_core/'
    API_LOGIN_URL = '/is_core/api/login/'

    @data_provider('create_user')
    def test_user_should_be_authorized_via_http_header(self, user):
        assert_http_redirect(self.get(self.INDEX_URL))
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_in('token', resp.json())
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_not_in('Authorization', self.c.cookies)
        assert_true(Token.objects.last().allowed_header)
        assert_false(Token.objects.last().allowed_cookie)

    @override_settings(AUTH_TOKEN_HEADER=False)
    @data_provider('create_user')
    def test_user_should_not_be_authorized_via_http_header_if_headers_are_turned_off(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_in('token', resp.json())
        assert_http_redirect(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_false(self.client.cookies)

    @override_settings(AUTH_TOKEN_HEADER_NAME='X-Authorization')
    @data_provider('create_user')
    def test_user_should_be_authorized_with_changed_header_name(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_in('token', resp.json())
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_X_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_http_redirect(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )

    @data_provider('create_user')
    def test_user_should_not_be_authorized_via_header_if_token_has_not_allowed_header(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        Token.objects.all().update(allowed_header=False)
        assert_http_redirect(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )

    @override_settings(AUTH_TOKEN_HEADER_TOKEN_TYPE=None)
    @data_provider('create_user')
    def test_user_should_be_authorized_via_header_without_token_type(self, user):

        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_http_redirect(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': resp.json()['token']})
        )

    @data_provider('create_user')
    def test_token_type_should_be_required(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_http_redirect(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': resp.json()['token']})
        )

    @data_provider('create_user')
    def test_token_should_be_updated_during_its_access(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        token = resp.json()['token']
        resp = self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        assert_in('X-Authorization-Expiration', resp)
        assert_true(resp['X-Authorization-Expiration'].startswith('0:59'))
        with freeze_time(timezone.now() + timedelta(minutes=10), tick=True):
            resp = self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
            assert_in('X-Authorization-Expiration', resp)
            assert_true(resp['X-Authorization-Expiration'].startswith('0:59'))

    @data_provider('create_user')
    def test_token_should_not_be_updated_during_its_access_if_request_contains_specific_haeader(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        token = resp.json()['token']
        resp = self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        assert_in('X-Authorization-Expiration', resp)
        assert_true(resp['X-Authorization-Expiration'].startswith('0:59'))
        with freeze_time(timezone.now() + timedelta(minutes=10), tick=True):
            resp = self.get(self.INDEX_URL, headers={
                'HTTP_AUTHORIZATION': 'Bearer {}'.format(token),
                'HTTP_X_AUTHORIZATION_RENEWAL_EXEMPT': '1'
            })
            assert_in('X-Authorization-Expiration', resp)
            assert_true(resp['X-Authorization-Expiration'].startswith('0:49'))

    @data_provider('create_user')
    def test_token_should_be_expired(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        token = resp.json()['token']
        resp = self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        assert_in('X-Authorization-Expiration', resp)
        assert_true(resp['X-Authorization-Expiration'].startswith('0:59'))
        with freeze_time(timezone.now() + timedelta(hours=1), tick=True):
            assert_http_redirect(self.get(self.INDEX_URL, headers={
                'HTTP_AUTHORIZATION': 'Bearer {}'.format(token),
            }))

    @data_provider('create_user')
    def test_user_should_be_logged_out_via_http_header(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        token = resp.json()['token']
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )
        assert_http_accepted(
            self.delete(self.API_LOGIN_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )
        assert_http_redirect(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )


class UILoginISCoreTestCase(BaseTestCaseMixin, ClientTestCase):

    INDEX_URL = '/is_core/'
    UI_LOGIN_URL = '/is_core/login/'
    UI_LOGOUT_URL = '/is_core/logout/'

    @data_provider('create_user')
    def test_user_should_be_authorized_via_cookie(self, user):
        assert_http_redirect(self.get(self.INDEX_URL))
        resp = self.post(self.UI_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_redirect(resp)
        assert_http_ok(self.get(self.INDEX_URL))
        assert_in('Authorization', self.c.cookies)
        assert_false(Token.objects.last().allowed_header)
        assert_true(Token.objects.last().allowed_cookie)

    @override_settings(AUTH_TOKEN_COOKIE=False)
    @data_provider('create_user')
    def test_user_should_not_be_authorized_via_cookie_if_cookie_is_turned_off(self, user):
        resp = self.post(self.UI_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_redirect(resp)
        assert_http_redirect(self.get(self.INDEX_URL))

    @override_settings(AUTH_TOKEN_COOKIE_NAME='ChangedAuthorization')
    @data_provider('create_user')
    def test_user_should_be_authorized_with_changed_cookie_name(self, user):
        resp = self.post(self.UI_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_redirect(resp)
        assert_in('ChangedAuthorization', self.c.cookies)
        assert_http_ok(self.get(self.INDEX_URL))

    @data_provider('create_user')
    def test_user_should_not_be_authorized_via_cookie_if_cookie_has_not_allowed_header(self, user):
        resp = self.post(self.UI_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_redirect(resp)
        assert_http_ok(self.get(self.INDEX_URL))
        assert_in('Authorization', self.c.cookies)
        Token.objects.all().update(allowed_cookie=False)
        assert_http_redirect(self.get(self.INDEX_URL))

    @data_provider('create_user')
    def test_user_should_be_logged_out_via_cookies(self, user):
        resp = self.post(self.UI_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_redirect(resp)
        assert_http_ok(self.get(self.INDEX_URL))
        assert_http_ok(self.get(self.UI_LOGOUT_URL))
        assert_http_redirect(self.get(self.INDEX_URL))
