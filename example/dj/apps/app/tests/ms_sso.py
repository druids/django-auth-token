import responses

from unittest.mock import patch

from germanium.test_cases.client import ClientTestCase
from germanium.tools import assert_is_none, assert_equal, assert_false

from auth_token.contrib.ms_sso.backends import MsSsoBackend
from auth_token.contrib.ms_sso.helpers import get_user_data

from .base import BaseTestCaseMixin


__all__ = (
    'MsSsoTestCase',
)


class MsSsoTestCase(BaseTestCaseMixin, ClientTestCase):

    def test_get_user_data_should_return_none_for_invalid_ms_response(self):
        with responses.RequestsMock() as resp:
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=401,
                content_type='application/json', json={
                    'error': {
                        'code': 'InvalidAuthenticationToken',
                        'message': 'Access token is empty.',
                        'innerError': {
                            'date': '2022-12-28T12:39:11',
                            'request-id': '373332eb-b369-4577-8c1b-62c075a22926',
                            'client-request-id': '373332eb-b369-4577-8c1b-62c075a22926'
                        }
                    }
                }
            )
            assert_is_none(get_user_data('token'))

    def test_get_user_data_should_return_user_data(self):
        with responses.RequestsMock() as resp:
            user_data = {
               'displayName': 'Adele Vance',
               'mail': 'AdeleV@contoso.onmicrosoft.com',
               'userPrincipalName': 'AdeleV@contoso.onmicrosoft.com',
               'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
            }
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                content_type='application/json', json=user_data
            )
            assert_equal(get_user_data('token'), user_data)

    def test_ms_sso_backend_should_not_authenticate_not_logged_user(self):
        with responses.RequestsMock() as resp:
            resp.add(responses.GET, 'https://graph.microsoft.com/v1.0/me', status=401, content_type='application/json')
            assert_is_none(MsSsoBackend().authenticate(None, 'token'))

    def test_ms_sso_backend_should_return_none_for_none_token(self):
        assert_is_none(MsSsoBackend().authenticate(None, None))

    def test_ms_sso_backend_should_return_none_for_not_existing_user(self):
        with responses.RequestsMock() as resp:
            user_data = {
                'displayName': 'Test Test',
                'mail': 'test@localhost',
                'userPrincipalName': 'test',
                'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
            }
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                content_type='application/json', json=user_data
            )
            assert_is_none(MsSsoBackend().authenticate(None, 'token'))

    def test_ms_sso_backend_should_return_the_right_user(self):
        user = self.create_user()
        with responses.RequestsMock() as resp:
            user_data = {
                'displayName': 'Test Test',
                'mail': 'test@localhost',
                'userPrincipalName': 'test',
                'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
            }
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                content_type='application/json', json=user_data
            )
            assert_equal(MsSsoBackend().authenticate(None, 'token'), user)

    def test_login_mso_callback_should_log_user(self):
        user = self.create_user()
        with patch('auth_token.contrib.ms_sso.views.get_sign_in_flow') as mocked_get_sign_in_flow:
            mocked_get_sign_in_flow.return_value = {
                'state': 'state',
                'redirect_uri': None,
                'scope': ['openid', 'profile', 'user.read', 'offline_access'],
                'auth_uri': 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize',
                'code_verifier': 'testverifier',
                'nonce': 'testnonce',
                'claims_challenge': None
            }
            response = self.get('/login/mso')
            assert_equal(response.status_code, 302)
            assert_equal(response['location'], 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize')
            with patch('auth_token.contrib.ms_sso.views.acquire_token_by_auth_code_flow') \
                    as mocked_acquire_token_by_auth_code_flow:
                mocked_acquire_token_by_auth_code_flow.return_value = {
                    'access_token': 'token'
                }
                with responses.RequestsMock() as resp:
                    user_data = {
                        'displayName': 'Test Test',
                        'mail': 'test@localhost',
                        'userPrincipalName': 'test',
                        'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
                    }
                    resp.add(
                        responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                        content_type='application/json', json=user_data
                    )
                    response = self.get('/login/mso/callback')
                    assert_equal(response.wsgi_request.user, user)
                    assert_equal(response.status_code, 302)
                    assert_equal(response['location'], '/')

    def test_login_mso_callback_without_access_token_should_not_log_user(self):
        with patch('auth_token.contrib.ms_sso.views.get_sign_in_flow') as mocked_get_sign_in_flow:
            mocked_get_sign_in_flow.return_value = {
                'state': 'state',
                'redirect_uri': None,
                'scope': ['openid', 'profile', 'user.read', 'offline_access'],
                'auth_uri': 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize',
                'code_verifier': 'testverifier',
                'nonce': 'testnonce',
                'claims_challenge': None
            }
            response = self.get('/login/mso')
            assert_equal(response.status_code, 302)
            assert_equal(response['location'], 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize')
            with patch('auth_token.contrib.ms_sso.views.acquire_token_by_auth_code_flow') \
                    as mocked_acquire_token_by_auth_code_flow:
                mocked_acquire_token_by_auth_code_flow.return_value = {}
                response = self.get('/login/mso/callback')
                assert_false(response.wsgi_request.user.is_authenticated)
                assert_equal(response.status_code, 302)
                assert_equal(response['location'], '/accounts/login/?next=/')

    def test_login_mso_callback_without_sign_flow_should_not_log_user(self):
        response = self.get('/login/mso/callback')
        assert_false(response.wsgi_request.user.is_authenticated)
        assert_equal(response.status_code, 302)
        assert_equal(response['location'], '/accounts/login/?next=')
