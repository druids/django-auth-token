from is_core.auth_token.default.resource import AuthResource as DefaultAuthResource
from is_core.auth_token.auth_security import LOGIN_THROTTLING_VALIDATORS

from security.models import InputLoggedRequest
from security.decorators import throttling


class AuthResource(DefaultAuthResource):

    @throttling(*LOGIN_THROTTLING_VALIDATORS)
    def post(self):
        return super(AuthResource, self).post()

    def _sucessful_login(self, request):
        if getattr(self.request, 'input_logged_request', False):
            self.request.input_logged_request.type = InputLoggedRequest.SUCCESSFUL_LOGIN_REQUEST

    def _unsucessful_login(self, request):
        if getattr(self.request, 'input_logged_request', False):
            self.request.input_logged_request.type = InputLoggedRequest.UNSUCCESSFUL_LOGIN_REQUEST
