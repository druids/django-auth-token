from germanium.annotations import data_provider
from germanium.test_cases.rest import RESTTestCase
from germanium.tools.http import assert_http_ok, assert_http_unauthorized, assert_http_accepted
from germanium.tools import assert_true, assert_false, assert_in, assert_not_in, assert_equal

from auth_token.models import Token, DeviceKey

from .base import BaseTestCaseMixin


__all__ = (
    'RESTFrameworkLoginISCoreTestCase',
    'DeviceKeyTestCase'
)

UUID = 'E621E1F8C36C495A93FC0C247A3E6E5F'
SHORTER_UUID = 'E621E1F8C36C495'
INDEX_URL = '/api/'
API_LOGIN_URL = '/api/login/'


class RESTFrameworkLoginISCoreTestCase(BaseTestCaseMixin, RESTTestCase):

    API_LOGOUT_URL = '/api/logout/'

    @data_provider('create_user')
    def test_user_should_be_authorized_via_http_header(self, user):
        assert_http_unauthorized(self.get(INDEX_URL))
        resp = self.post(API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_in('token', resp.json())
        assert_http_ok(
            self.get(INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_not_in('Authorization', self.c.cookies)
        assert_true(Token.objects.last().allowed_header)
        assert_false(Token.objects.last().allowed_cookie)

    @data_provider('create_user')
    def test_user_should_be_logged_out_via_http_header(self, user):
        resp = self.post(API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        token = resp.json()['token']
        assert_http_ok(
            self.get(INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )
        assert_http_accepted(
            self.delete(self.API_LOGOUT_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )
        assert_http_unauthorized(
            self.get(INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )


class DeviceKeyTestCase(BaseTestCaseMixin, RESTTestCase):

    API_REQUEST_MOBILE_TOKEN_URL = '/api/mobile-request-token/'
    API_MOBILE_LOGIN_URL = '/api/mobile-login/'

    @data_provider('create_user')
    def test_user_should_be_authorized_from_token_and_uuid(self, user):

        device_token = DeviceKey.objects.get_or_create_token(uuid=UUID, user=user)[0]
        resp = self.post(self.API_MOBILE_LOGIN_URL,
                         {'uuid': UUID, 'login_device_token': device_token})
        assert_http_ok(resp)
        assert_in('token', resp.json())
        assert_http_ok(
            self.get(INDEX_URL, headers={
                'HTTP_AUTHORIZATION': 'Bearer {}'.format(
                    resp.json()['token'])})
        )
        assert_not_in('Authorization', self.c.cookies)
        assert_true(Token.objects.last().allowed_header)
        assert_false(Token.objects.last().allowed_cookie)

    @data_provider('create_user')
    def test_user_should_be_authorized_from_token_and_shorter_uuid(self, user):

        device_token = DeviceKey.objects.get_or_create_token(uuid=SHORTER_UUID, user=user)[0]
        resp = self.post(self.API_MOBILE_LOGIN_URL,
                         {'uuid': SHORTER_UUID, 'login_device_token': device_token})
        assert_http_ok(resp)

    @data_provider('create_user')
    def test_user_should_get_token_when_device_registered_by_uuid(self, user):
        logged_in_resp = self.post(API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        registration_mobile_resp = self.post(self.API_REQUEST_MOBILE_TOKEN_URL, headers={
            'HTTP_AUTHORIZATION': 'Bearer {}'.format(
                logged_in_resp.json()['token'])}, data={'uuid': UUID})
        assert_http_ok(registration_mobile_resp)
        mobile_token = registration_mobile_resp.json()['device_login_token']
        device_keys = DeviceKey.objects.all()
        assert_equal(1, device_keys.count())
        device_key = device_keys[0]
        assert_true(device_key.check_password(mobile_token))
        assert_false(device_key.check_password('XXX'))
