from django.contrib.auth.views import LoginView

from auth_token.contrib.common.default.views import TokenLoginView as DefaultTokenLoginView

from security.decorators import throttling_all
from security.enums import InputRequestSlug

from .validators import LOGIN_THROTTLING_VALIDATORS


@throttling_all(*LOGIN_THROTTLING_VALIDATORS)
class TokenLoginView(DefaultTokenLoginView):

    def form_valid(self, form):
        input_request_logger = getattr(self.request, 'input_request_logger', None)
        if input_request_logger:
            input_request_logger.set_slug(InputRequestSlug.SUCCESSFUL_LOGIN_REQUEST)
        return super().form_valid(form)

    def form_invalid(self, form):
        input_request_logger = getattr(self.request, 'input_request_logger', None)
        if input_request_logger:
            input_request_logger.set_slug(InputRequestSlug.UNSUCCESSFUL_LOGIN_REQUEST)
        return super().form_invalid(form)


@throttling_all(*LOGIN_THROTTLING_VALIDATORS)
class LoginCodeVerificationView(LoginView):
    pass


class InputLogMixin:

    def log_successful_request(self):
        input_request_logger = getattr(self.request, 'input_request_logger', None)
        if input_request_logger:
            input_request_logger.set_slug(InputRequestSlug.SUCCESSFUL_2FA_CODE_VERIFICATION_REQUEST)

    def log_unsuccessful_request(self):
        input_request_logger = getattr(self.request, 'input_request_logger', None)
        if input_request_logger:
            input_request_logger.set_slug(InputRequestSlug.UNSUCCESSFUL_2FA_CODE_VERIFICATION_REQUEST)
