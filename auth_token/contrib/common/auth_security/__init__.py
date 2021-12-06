from django.core.exceptions import ImproperlyConfigured

from security.utils import get_throttling_validators
from security.throttling.validators import (
    SuccessfulLoginThrottlingValidator, SuccessfulTwoFactorCodeVerificationThrottlingValidator,
    UnsuccessfulLoginThrottlingValidator, UnSuccessfulTwoFactorCodeVerificationThrottlingValidator
)


try:
    LOGIN_THROTTLING_VALIDATORS = get_throttling_validators('is_core_login_validators')
except ImproperlyConfigured:
    LOGIN_THROTTLING_VALIDATORS = (
        UnsuccessfulLoginThrottlingValidator(60, 2),
        UnsuccessfulLoginThrottlingValidator(10 * 60, 10),
        SuccessfulLoginThrottlingValidator(60, 2),
        SuccessfulLoginThrottlingValidator(10 * 60, 10),
        UnSuccessfulTwoFactorCodeVerificationThrottlingValidator(60, 2),
        UnSuccessfulTwoFactorCodeVerificationThrottlingValidator(10 * 60, 10),
        SuccessfulTwoFactorCodeVerificationThrottlingValidator(60, 2),
        SuccessfulTwoFactorCodeVerificationThrottlingValidator(10 * 60, 10),
    )
