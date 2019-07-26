from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.hashers import make_password
from django.test import override_settings
from django.utils import timezone
from django.utils.translation import ugettext as _
from nose.tools import assert_equal

from auth_token.config import settings
from auth_token.models import Token
from freezegun import freeze_time
from germanium.annotations import data_provider
from germanium.test_cases.client import ClientTestCase
from germanium.test_cases.rest import RESTTestCase
from germanium.tools import assert_false, assert_in, assert_not_in, assert_true
from germanium.tools.http import (assert_http_accepted, assert_http_ok,
                                  assert_http_redirect)

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
    UI_TWO_FACTOR_LOGIN_URL = '/two-factor-login/'
    UI_CODE_CHECK_LOGIN_URL = '/login-code-verification/'
    CODE = '12345'

    def send_two_factor_token(token, code):
        pass

    def generate_code(self):
        return UILoginISCoreTestCase.CODE

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

    @override_settings(AUTH_TOKEN_TWO_FACTOR_ENABLED=True)
    @override_settings(
        AUTH_TOKEN_TWO_FACTOR_SENDING_FUNCTION='app.tests.is_core.UILoginISCoreTestCase.send_two_factor_token')
    @data_provider('create_user')
    def test_user_should_be_authorized_with_two_factor_authentication(self, user):
        login_resp = self.post(self.UI_TWO_FACTOR_LOGIN_URL, {'username': 'test', 'password': 'test'})

        assert_http_redirect(login_resp)
        resp_location = login_resp['Location']
        assert_equal(resp_location[:resp_location.find('?')], settings.TWO_FACTOR_REDIRECT_URL)
        assert_false(login_resp.wsgi_request.user.is_authenticated)

        token = login_resp.wsgi_request.token
        assert_true(token.two_factor_code is not None)
        assert_false(token.is_authenticated)
        # the code value needs to be overwritted, so that its value could be used for next request
        token.two_factor_code = make_password('12345', salt=Token.TWO_FACTOR_CODE_SALT)
        token.save()

        code_check_resp = self.post(self.UI_CODE_CHECK_LOGIN_URL, {'code': '12345'})

        assert_http_redirect(code_check_resp)
        assert_equal(code_check_resp['location'], '/accounts/profile/')
        assert_true(code_check_resp.wsgi_request.token.is_authenticated)
        assert_true(code_check_resp.wsgi_request.user.is_authenticated)
        assert_equal(code_check_resp.wsgi_request.user, user)

    @override_settings(AUTH_TOKEN_TWO_FACTOR_ENABLED=True)
    @override_settings(
        AUTH_TOKEN_TWO_FACTOR_SENDING_FUNCTION='app.tests.is_core.UILoginISCoreTestCase.send_two_factor_token')
    @override_settings(
        AUTH_TOKEN_TWO_FACTOR_CODE_GENERATING_FUNCTION='app.tests.is_core.UILoginISCoreTestCase.generate_code')
    @patch('app.tests.is_core.UILoginISCoreTestCase.send_two_factor_token')
    def test_send_two_factor_token_should_be_called_for_two_factor_login(self, send_two_factor_token):
        self.create_user()
        login_resp = self.post(self.UI_TWO_FACTOR_LOGIN_URL, {'username': 'test', 'password': 'test'})

        assert_http_redirect(login_resp)
        send_two_factor_token.assert_called_once_with(login_resp.wsgi_request.token, self.CODE)

    @override_settings(AUTH_TOKEN_TWO_FACTOR_ENABLED=True)
    @override_settings(
        AUTH_TOKEN_TWO_FACTOR_SENDING_FUNCTION='app.tests.is_core.UILoginISCoreTestCase.send_two_factor_token')
    @data_provider('create_user')
    def test_user_should_not_be_logged_in_two_factor_for_invalid_code(self, user):
        login_resp = self.post(self.UI_TWO_FACTOR_LOGIN_URL, {'username': 'test', 'password': 'test'})

        assert_http_redirect(login_resp)
        # the code value needs to be overwritten, so that its value could be used for next request
        login_resp.wsgi_request.token.two_factor_code = make_password('12345', salt=Token.TWO_FACTOR_CODE_SALT)
        login_resp.wsgi_request.token.save()

        code_check_resp = self.post(self.UI_CODE_CHECK_LOGIN_URL, {'code': 'other_code'})

        assert_http_ok(code_check_resp)
        assert_in(
            _('The inserted value does not correspond to the sent code.'),
            code_check_resp._container[0].decode('utf8')
        )
        assert_false(code_check_resp.wsgi_request.token.is_authenticated)
