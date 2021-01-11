from germanium.decorators import data_consumer
from germanium.test_cases.client import ClientTestCase
from germanium.tools.http import assert_http_ok, assert_http_redirect
from germanium.tools import assert_true, assert_false, assert_in

from auth_token.models import AuthorizationToken

from .base import BaseTestCaseMixin


__all__ = (
   'AdminLoginISCoreTestCase',
)


class AdminLoginISCoreTestCase(BaseTestCaseMixin, ClientTestCase):

    INDEX_URL = '/admin/'
    LOGIN_URL = '/admin/login/'
    LOGOUT_URL = '/admin/logout/'

    @data_consumer('create_user')
    def test_user_should_log_and_logout_to_the_administration(self, user):
        assert_http_redirect(self.get(self.INDEX_URL))
        resp = self.post(self.LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_http_redirect(resp)
        assert_http_ok(self.get(self.INDEX_URL))
        assert_in('Authorization', self.c.cookies)
        assert_false(AuthorizationToken.objects.last().allowed_header)
        assert_true(AuthorizationToken.objects.last().allowed_cookie)
        assert_http_ok(self.get(self.LOGOUT_URL))
        assert_http_redirect(self.get(self.INDEX_URL))

