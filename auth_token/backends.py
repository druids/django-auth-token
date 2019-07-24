from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from auth_token.models import DeviceKey


class DeviceBackend(ModelBackend):
    """
    Authenticates device with UUID and login_token (password)
    """

    def authenticate(self, device_uuid=None, mobile_login_token=None, **kwargs):
        if not device_uuid or not mobile_login_token:
            return None

        device_key_qs = DeviceKey.objects.filter(uuid=device_uuid, is_active=True)
        if not device_key_qs.exists():
            raise PermissionDenied(
                'DeviceKey with device_uuid "{}" not found.'.format(device_uuid))

        for device_key in device_key_qs:
            if device_key.check_password(mobile_login_token):
                user = self.get_user(device_key.user_id)
                if user:
                    device_key.last_login = timezone.now()
                    device_key.save()
                    return user
                else:
                    return None

        raise PermissionDenied('Provided invalid login_token to DeviceKey with device_uuid "{}".'.format(device_uuid))
