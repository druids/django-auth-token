from auth_token.config import settings
from auth_token.utils import create_otp, deactivate_otp, get_valid_otp, otp_key_generator_factory
from auth_token.models import MobileDevice


class BaseAuthorizationRequestBackend:

    def initialize(self, authorization_request):
        """
        Initialize backend for the authorization request. It is called with create new autorization or its reset.
        Args:
            authorization_request: AuthorizationRequest instance.
        """
        pass

    def authenticate(self, authorization_request, **kwargs):
        """
        Check if authorization input data is valid and can grant its access.
        Args:
            authorization_request: AuthorizationRequest instance.
            **kwargs: input data to check access.

        Return:
            True/False if input data are valid.
        """
        raise NotImplementedError

    def grant(self, authorization_request):
        """
        Method is called when authorization request was granted.
        Args:
            authorization_request: AuthorizationRequest instance.
        """
        pass

    def deny(self, authorization_request):
        """
        Method is called when authorization request was denied.
        Args:
            authorization_request: AuthorizationRequest instance.
        """
        pass

    def cancel(self, authorization_request):
        """
        Method is called when authorization request was cancelled.
        Args:
            authorization_request: AuthorizationRequest instance.
        """
        pass


default_otp_authorization_request_generator = otp_key_generator_factory(
    characters=settings.AUTHORIZATION_OTP_BACKEND_DEFAULT_KEY_GENERATOR_CHARACTERS,
    length=settings.AUTHORIZATION_OTP_BACKEND_DEFAULT_KEY_GENERATOR_LENGTH
)


class OTPAuthorizationRequestBackend(BaseAuthorizationRequestBackend):
    """
    Backend for authorization request authentication via OTP.
    """

    def _create_otp(self, authorization_request):
        return create_otp(
            authorization_request.slug,
            expiration=(authorization_request.expires_at - authorization_request.created_at).total_seconds(),
            related_objects=[authorization_request],
            deactivate_old=True,
            key_generator=settings.AUTHORIZATION_OTP_BACKEND_DEFAULT_KEY_GENERATOR
        )

    def initialize(self, authorization_request):
        otp = self._create_otp(authorization_request)
        authorization_request.secret_key = otp.secret_key

    def authenticate(self, authorization_request, otp_secret_key=None, **kwargs):
        if otp_secret_key is None:
            return False

        if (settings.AUTHORIZATION_REQUEST_OTP_DEBUG_CODE
                and settings.AUTHORIZATION_REQUEST_OTP_DEBUG_CODE == otp_secret_key):
            otp_secret_key = None

        otp = get_valid_otp(authorization_request.slug, key=otp_secret_key, related_objects=[authorization_request])
        return otp is not None

    def _deactivate(self, authorization_request):
        deactivate_otp(authorization_request.slug, related_objects=[authorization_request])

    def grant(self, authorization_request):
        self._deactivate(authorization_request)

    def deny(self, authorization_request):
        self._deactivate(authorization_request)

    def cancel(self, authorization_request):
        self._deactivate(authorization_request)


class MobileDeviceAuthorizationRequestBackend(BaseAuthorizationRequestBackend):
    """
    Backend for authorization request authentication vie user mobile device.
    """

    def _get_valid_mobile_device(self, mobile_device_uuid=None, mobile_login_token=None):
        for mobile_device in MobileDevice.objects.filter(uuid=mobile_device_uuid, is_active=True):
            if mobile_device.check_password(mobile_login_token):
                return mobile_device
        return None

    def authenticate(self, authorization_request, mobile_device_uuid=None, mobile_login_token=None, **kwargs):
        valid_mobile_device = None
        if mobile_device_uuid and mobile_login_token:
            valid_mobile_device = self._get_valid_mobile_device(mobile_device_uuid, mobile_login_token)

        return valid_mobile_device is not None and valid_mobile_device.user == authorization_request.user
