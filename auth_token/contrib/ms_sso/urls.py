from django.urls import path

from .views import MsCallback, MsLogin


urlpatterns = [
    path(
        'login/mso',
        MsLogin.as_view(),
        name='ms-sso-login',
    ),
    path(
        'login/mso/callback',
        MsCallback.as_view(),
        name='ms-sso-redirect',
    ),
]
