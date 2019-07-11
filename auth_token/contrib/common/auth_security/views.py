from django.contrib.auth.views import LoginView

from auth_token.contrib.common.auth_security import LOGIN_THROTTLING_VALIDATORS
from auth_token.contrib.common.default.views import TokenLoginView as DefaultTokenLoginView
from security.decorators import throttling_all
from security.models import InputLoggedRequest


@throttling_all(*LOGIN_THROTTLING_VALIDATORS)
class TokenLoginView(DefaultTokenLoginView):

    def form_valid(self, form):
        if getattr(self.request, 'input_logged_request', False):
            self.request.input_logged_request.type = InputLoggedRequest.SUCCESSFUL_LOGIN_REQUEST
        return super().form_valid(form)

    def form_invalid(self, form):
        if getattr(self.request, 'input_logged_request', False):
            self.request.input_logged_request.type = InputLoggedRequest.UNSUCCESSFUL_LOGIN_REQUEST
        return super().form_invalid(form)


@throttling_all(*LOGIN_THROTTLING_VALIDATORS)
class LoginCodeVerificationView(LoginView):
    pass


class InputLogMixin:

    def log_successful_request(self):
        if getattr(self.request, 'input_logged_request', False):
            self.request.input_logged_request.type = InputLoggedRequest.SUCCESSFUL_2FA_CODE_VERIFICATION_REQUEST

    def log_unsuccessful_request(self):
        if getattr(self.request, 'input_logged_request', False):
            self.request.input_logged_request.type = InputLoggedRequest.UNSUCCESSFUL_2FA_CODE_VERIFICATION_REQUEST