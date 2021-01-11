from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from auth_token.models import MobileDevice


class DeviceBackend(ModelBackend):
    """
    Authenticates device with UUID and login_token (password)
    """

    def authenticate(self, request, mobile_device_id=None, mobile_login_token=None, **kwargs):
        if not mobile_device_id or not mobile_login_token:
            return None

        mobile_device_qs = MobileDevice.objects.filter(uuid=mobile_device_id, is_active=True)
        if not mobile_device_qs.exists():
            raise PermissionDenied('MobileDevice with id "{}" not found.'.format(mobile_device_id))

        for mobile_device in mobile_device_qs:
            if mobile_device.check_password(mobile_login_token):
                user = self.get_user(mobile_device.user_id)
                if user:
                    mobile_device.last_login = timezone.now()
                    mobile_device.save()
                    user.authenticated_mobile_device = mobile_device
                    return user
                else:
                    return None

        raise PermissionDenied('Provided invalid login_token to MobileDevice with id "{}".'.format(mobile_device_id))
