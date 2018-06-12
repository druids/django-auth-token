from germanium.tools.rest import assert_valid_JSON_response

from is_core.config import settings as is_core_settings

from auth_token.config import settings
from auth_token.utils import header_name_to_django, create_auth_header_value


class RESTAuthMixin:

    def authorize(self, username, password):
        resp = self.post(
            is_core_settings.LOGIN_API_URL,
            data={is_core_settings.USERNAME: username, is_core_settings.PASSWORD: password}
        )
        assert_valid_JSON_response(resp, 'REST authorization fail: %s' % resp)
        self.default_headers[header_name_to_django(settings.HEADER_NAME)] = (
            create_auth_header_value(self.deserialize(resp).get('token'))
        )
