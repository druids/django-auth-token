from germanium.decorators import data_consumer
from germanium.test_cases.rest import RestTestCase
from germanium.tools.http import assert_http_ok, assert_http_unauthorized, assert_http_accepted, assert_http_bad_request
from germanium.tools import assert_true, assert_false, assert_in, assert_not_in, assert_equal

from auth_token.models import AuthorizationToken, MobileDevice

from .base import BaseTestCaseMixin


__all__ = (
    'RestFrameworkLoginISCoreTestCase',
    'DeviceKeyTestCase'
)

UUID = 'E621E1F8C36C495A93FC0C247A3E6E5F'
SHORTER_UUID = 'E621E1F8C36C495'
INDEX_URL = '/api/'
API_LOGIN_URL = '/api/login/'


class RestFrameworkLoginISCoreTestCase(BaseTestCaseMixin, RestTestCase):

    API_LOGOUT_URL = '/api/logout/'

    @data_consumer('create_user')
    def test_user_should_be_authorized_via_http_header(self, user):
        assert_http_unauthorized(self.get(INDEX_URL))
        resp = self.post(API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_in('token', resp.json())
        assert_http_ok(
            self.get(INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_not_in('Authorization', self.c.cookies)
        assert_true(AuthorizationToken.objects.last().allowed_header)
        assert_false(AuthorizationToken.objects.last().allowed_cookie)

    @data_consumer('create_user')
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


class DeviceKeyTestCase(BaseTestCaseMixin, RestTestCase):

    API_REQUEST_MOBILE_TOKEN_URL = '/api/mobile-request-token/'
    API_MOBILE_LOGIN_URL = '/api/mobile-login/'

    @data_consumer('create_user')
    def test_user_should_be_authorized_from_token_and_uuid(self, user):
        device_token = MobileDevice.objects.activate_or_create(uuid=UUID, user=user).secret_password
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
        assert_true(AuthorizationToken.objects.last().allowed_header)
        assert_false(AuthorizationToken.objects.last().allowed_cookie)

    @data_consumer('create_user')
    def test_user_should_be_authorized_from_token_and_shorter_uuid(self, user):

        device_token = MobileDevice.objects.activate_or_create(uuid=SHORTER_UUID, user=user).secret_password
        resp = self.post(self.API_MOBILE_LOGIN_URL,
                         {'uuid': SHORTER_UUID, 'login_device_token': device_token})
        assert_http_ok(resp)

    @data_consumer('create_user')
    def test_user_should_get_token_when_device_registered_by_uuid(self, user):
        logged_in_resp = self.post(API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        registration_mobile_resp = self.post(self.API_REQUEST_MOBILE_TOKEN_URL, headers={
            'HTTP_AUTHORIZATION': 'Bearer {}'.format(
                logged_in_resp.json()['token'])}, data={'uuid': UUID})
        assert_http_ok(registration_mobile_resp)
        mobile_token = registration_mobile_resp.json()['device_login_token']
        device_keys = MobileDevice.objects.all()
        assert_equal(1, device_keys.count())
        device_key = device_keys[0]
        assert_true(device_key.check_password(mobile_token))
        assert_false(device_key.check_password('XXX'))

    @data_consumer('create_user')
    def test_user_should_not_register_same_device_keys(self, user):
        logged_in_resp = self.post(API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        registration_mobile_resp = self.post(self.API_REQUEST_MOBILE_TOKEN_URL, headers={
            'HTTP_AUTHORIZATION': 'Bearer {}'.format(
                logged_in_resp.json()['token'])}, data={'uuid': UUID})
        assert_http_ok(registration_mobile_resp)
        registration_mobile_resp = self.post(self.API_REQUEST_MOBILE_TOKEN_URL, headers={
            'HTTP_AUTHORIZATION': 'Bearer {}'.format(
                logged_in_resp.json()['token'])}, data={'uuid': UUID})
        assert_http_bad_request(registration_mobile_resp)

    def create_users(self):
        return [
            (i, self.create_user('test{}'.format(i), 'test{}@test.cz'.format(i), 'test{}'.format(i))) for i in range(5)
        ]

    @data_consumer('create_users')
    def test_different_users_should_register_and_authorize_with_same_device_keys(self, i, user):
        logged_in_resp = self.post(API_LOGIN_URL, {'username': 'test{}'.format(i), 'password': 'test{}'.format(i)})
        registration_mobile_resp = self.post(self.API_REQUEST_MOBILE_TOKEN_URL, headers={
            'HTTP_AUTHORIZATION': 'Bearer {}'.format(
                logged_in_resp.json()['token'])}, data={'uuid': UUID})
        assert_http_ok(registration_mobile_resp)
        registration_mobile_resp = self.post(self.API_REQUEST_MOBILE_TOKEN_URL, headers={
            'HTTP_AUTHORIZATION': 'Bearer {}'.format(
                logged_in_resp.json()['token'])}, data={'uuid': UUID})
        assert_http_bad_request(registration_mobile_resp)
