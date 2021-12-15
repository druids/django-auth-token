from auth_token.contrib.common.auth_security.validators import LOGIN_THROTTLING_VALIDATORS
from auth_token.contrib.is_core_auth.default.resource import AuthResource as DefaultAuthResource

from security.enums import InputRequestSlug
from security.decorators import throttling
from security.utils import update_logged_request_data


class AuthResource(DefaultAuthResource):

    @throttling(*LOGIN_THROTTLING_VALIDATORS)
    def post(self):
        return super().post()

    def _sucessful_login(self, request):
        update_logged_request_data(self.request, slug=InputRequestSlug.SUCCESSFUL_LOGIN_REQUEST)
        return super()._sucessful_login(request)

    def _unsucessful_login(self, request):
        update_logged_request_data(self.request, slug=InputRequestSlug.UNSUCCESSFUL_LOGIN_REQUEST)
        return super()._unsucessful_login(request)
