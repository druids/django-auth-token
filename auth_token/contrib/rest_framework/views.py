from rest_framework.compat import coreapi, coreschema
from rest_framework.response import Response
from rest_framework.schemas import ManualSchema
from rest_framework.views import APIView

from auth_token.utils import login, logout

from .serializers import AuthTokenSerializer


class LoginAuthToken(APIView):

    throttle_classes = ()
    permission_classes = ()
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
                    schema=coreschema.String(
                        title='Permanent',
                        description='Define if login can expire',
                    ),
                ),
            ],
            encoding='application/json',
        )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        login(request._request, user, not serializer.validated_data['permanent'])
        return Response({'token': request._request.token.key})


class LogoutAuthToken(APIView):

    def delete(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request._request)
        return Response(status=204)
