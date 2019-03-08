from auth_token.contrib.common.views import LoginView as _LoginView
from auth_token.contrib.common.views import LogoutView as _LogoutView
from auth_token.models import DeviceKey
from auth_token.utils import login, logout
from rest_framework.compat import coreapi, coreschema
from rest_framework.response import Response
from rest_framework.schemas import ManualSchema
from rest_framework.views import APIView

from .serializers import (
    AuthTokenSerializer, MobileAuthTokenSerializer, MobileAuthTokenRegisterSerializer
)


class LoginAuthToken(APIView):

    throttle_classes = ()
    permission_classes = ()
    authentication_classes = ()
    serializer_class = AuthTokenSerializer
    if coreapi is not None and coreschema is not None:
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name='username',
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title='Username',
                        description='Valid username for authentication',
                    ),
                ),
                coreapi.Field(
                    name='password',
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title='Password',
                        description='Valid password for authentication',
                    ),
                ),
                coreapi.Field(
                    name='permanent',
                    required=False,
                    location='form',
                    schema=coreschema.Boolean(
                        title='Permanent',
                        description='Define if login can expire',
                    ),
                ),
            ],
            encoding='application/json',
        )
    allowed_cookie = False
    allowed_header = True

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        login(
            request._request, user, not serializer.validated_data.get('permanent', False),
            allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header
        )
        return Response({'token': request._request.token.key})


class MobileLoginAuthToken(APIView):

    throttle_classes = ()
    permission_classes = ()
    authentication_classes = ()
    serializer_class = MobileAuthTokenSerializer
    if coreapi is not None and coreschema is not None:
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name='uuid',
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title='Device UUID',
                        description='Valid device UUID for authentication',
                    ),
                ),
                coreapi.Field(
                    name='login_device_token',
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title='Password',
                        description='Valid token for authentication',
                    ),
                ),
            ],
            encoding='application/json',
        )
    allowed_cookie = False
    allowed_header = True

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        login(
            request._request, user,
            allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header
        )
        return Response({'token': request._request.token.key})


class LogoutAuthToken(APIView):

    def delete(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request._request)
        return Response(status=204)


class MobileRegisterToken(APIView):

    serializer_class = MobileAuthTokenRegisterSerializer
    if coreapi is not None and coreschema is not None:
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name='uuid',
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title='Device UUID',
                        description='Valid device UUID for authentication',
                    ),
                ),
            ],
            encoding='application/json',
        )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        uuid = serializer.validated_data['uuid']
        device_token = DeviceKey.objects.get_or_create_token(uuid=uuid, user=request.user)[0]

        return Response({'device_login_token': device_token})


class LoginView(_LoginView):

    template_name = 'rest_framework_auth/login.html'


class LogoutView(_LogoutView):

    template_name = None

    def get_next_page(self):
        return super().get_next_page() or '/'
