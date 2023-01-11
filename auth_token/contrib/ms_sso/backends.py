from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .helpers import get_user_data


UserModel = get_user_model()


class MsSsoBackend(ModelBackend):
    """
    Authenticates device with MS SSO
    """

    def _get_user_from_ms_user_data(self, ms_user_data):
        username = ms_user_data['userPrincipalName']
        try:
            return UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            return None

    def authenticate(self, request, mso_token=None, **kwargs):
        if not mso_token:
            return None

        ms_user_data = get_user_data(mso_token)
        if not ms_user_data:
            return None

        user = self._get_user_from_ms_user_data(ms_user_data)
        if user and self.user_can_authenticate(user):
            return user
        else:
            return None
