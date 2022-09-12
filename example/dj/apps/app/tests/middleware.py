from datetime import timedelta

from django.test import override_settings
from django.utils.timezone import localtime

from freezegun import freeze_time
from germanium.decorators import data_consumer
from germanium.test_cases.rest import RestTestCase
from germanium.tools import assert_equal, assert_not_equal
from germanium.tools.http import assert_http_ok

from auth_token.models import AuthorizationToken

from .base import BaseTestCaseMixin


__all__ = (
    'MiddlewareTestCase',
)


class MiddlewareTestCase(BaseTestCaseMixin, RestTestCase):

    LOGIN_URL = '/is_core/api/login/'
    INDEX_URL = '/is_core/'

    def _get_auth_header(self, token):
        return {'HTTP_AUTHORIZATION': 'Bearer {}'.format(token)}

    @override_settings(AUTH_TOKEN_EXPIRATION_DELTA=60)
    @data_consumer('create_user')
    def test_token_middleware_should_respect_expiration_delta_setting(self, user):
        response = self.post(self.LOGIN_URL, {'username': 'test', 'password': 'test'})
        assert_equal(AuthorizationToken.objects.count(), 1)

        token = response.json()['token']
        token_obj = AuthorizationToken.objects.last()
        expires_at = token_obj.expires_at

        with freeze_time(localtime() + timedelta(seconds=59)):
            self.get(self.INDEX_URL, headers=self._get_auth_header(token))
            assert_equal(expires_at, token_obj.refresh_from_db().expires_at)

        with freeze_time(localtime() + timedelta(seconds=60)):
            self.get(self.INDEX_URL, headers=self._get_auth_header(token))
            assert_not_equal(expires_at, token_obj.refresh_from_db().expires_at)
