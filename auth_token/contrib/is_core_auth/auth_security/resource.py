from auth_token.contrib.common.auth_security.validators import LOGIN_THROTTLING_VALIDATORS
from auth_token.contrib.is_core_auth.default.resource import AuthResource as DefaultAuthResource

from security.enums import InputRequestSlug
from security.models import InputLoggedRequest
from security.decorators import throttling


class AuthResource(DefaultAuthResource):

    @throttling(*LOGIN_THROTTLING_VALIDATORS)
    def post(self):
        return super().post()

    def _sucessful_login(self, request):
        input_request_logger = getattr(self.request, 'input_request_logger', None)
        if input_request_logger:
            input_request_logger.set_slug(InputRequestSlug.SUCCESSFUL_LOGIN_REQUEST)
        return super().form_valid(form)

    def _unsucessful_login(self, request):
        input_request_logger = getattr(self.request, 'input_request_logger', None)
        if input_request_logger:
            input_request_logger.set_slug(InputRequestSlug.UNSUCCESSFUL_LOGIN_REQUEST)
        return super().form_invalid(form)
