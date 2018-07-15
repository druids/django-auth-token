from datetime import timedelta

from django.utils import timezone

from germanium.annotations import data_provider
from germanium.test_cases.default import GermaniumTestCase
from germanium.tools import assert_equal, assert_true, assert_false

from auth_token.models import Token
from auth_token.config import settings

from .base import BaseTestCaseMixin


__all__ = (
    'TokenTestCase',
)


class TokenTestCase(BaseTestCaseMixin, GermaniumTestCase):

    @data_provider('create_user')
    def test_should_return_proper_string_format_for_expiration(self, user):
        expired_token = Token.objects.create(user=user, ip='127.0.0.1')
        Token.objects.filter(pk=expired_token.pk).update(
            last_access=timezone.now() - timedelta(seconds=settings.MAX_TOKEN_AGE))
        expired_token = Token.objects.get(pk=expired_token.pk)
        assert_equal('00:00:00', Token.objects.get(pk=expired_token.pk).str_time_to_expiration)

        non_expired_token = Token.objects.create(user=user, ip='127.0.0.1')
        assert_equal('0:59:59', non_expired_token.str_time_to_expiration.split('.')[0])
