from germanium.annotations import data_provider
from germanium.test_cases.rest import RESTTestCase
from germanium.tools.http import assert_http_ok, assert_http_unauthorized, assert_http_accepted
from germanium.tools import assert_true, assert_false, assert_in, assert_not_in

from auth_token.models import Token

from .base import BaseTestCaseMixin


__all__ = (
   'RESTFrameworkLoginISCoreTestCase',
)


class RESTFrameworkLoginISCoreTestCase(BaseTestCaseMixin, RESTTestCase):

    INDEX_URL = '/api/'
    API_LOGIN_URL = '/api/login/'
    API_LOGOUT_URL = '/api/logout/'

    @data_provider('create_user')
    def test_user_should_be_authorized_via_http_header(self, user):
        assert_http_unauthorized(self.get(self.INDEX_URL))
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        assert_in('token', resp.json())
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(resp.json()['token'])})
        )
        assert_not_in('Authorization', self.c.cookies)
        assert_true(Token.objects.last().allowed_header)
        assert_false(Token.objects.last().allowed_cookie)

    @data_provider('create_user')
    def test_user_should_be_logged_out_via_http_header(self, user):
        resp = self.post(self.API_LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_ok(resp)
        token = resp.json()['token']
        assert_http_ok(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )
        assert_http_accepted(
            self.delete(self.API_LOGOUT_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )
        assert_http_unauthorized(
            self.get(self.INDEX_URL, headers={'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)})
        )
