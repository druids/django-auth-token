from django.conf import settings
from django.conf.urls import url, include
from django.contrib import admin

from app.resource import SimpleAPI
from auth_token.contrib.admin.views import LoginView as AdminLoginView
from auth_token.contrib.admin.views import LogoutView as AdminLogoutView
from auth_token.contrib.is_core_auth.views import LoginCodeVerificationView, TwoFactorLoginView
from auth_token.contrib.rest_framework_auth.views import LoginView as RestFrameworkLoginView
from auth_token.contrib.rest_framework_auth.views import LogoutView as RestFrameworkLogoutView
from auth_token.contrib.rest_framework_auth.views import (
    LoginAuthToken, LogoutAuthToken, MobileLoginAuthToken, MobileRegisterToken
)
from is_core.site import site as is_core_site

admin.site.login = AdminLoginView.as_view()
admin.site.logout = AdminLogoutView.as_view()

urlpatterns = [
    url('admin/', admin.site.urls),
    url('is_core/', include(is_core_site.urls)),
    url('two-factor-login/', TwoFactorLoginView.as_view()),
    url('login-code-verification/', LoginCodeVerificationView.as_view()),
    url('api/login/', LoginAuthToken.as_view()),
    url('api/logout/', LogoutAuthToken.as_view()),
    url('api/mobile-login/', MobileLoginAuthToken.as_view()),
    url('api/mobile-request-token/', MobileRegisterToken.as_view()),
    url('api/docs/login/', RestFrameworkLoginView.as_view()),
    url('api/docs/logout/', RestFrameworkLogoutView.as_view()),
    url('api/', SimpleAPI.as_view())
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
