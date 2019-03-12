from django.conf import settings
from django.conf.urls import include
from django.contrib import admin
from django.urls import path

from app.resource import SimpleAPI
from auth_token.contrib.admin.views import LoginView as AdminLoginView
from auth_token.contrib.admin.views import LogoutView as AdminLogoutView
from auth_token.contrib.rest_framework_auth.views import LoginView as RESTFrameworkLoginView
from auth_token.contrib.rest_framework_auth.views import LogoutView as RESTFrameworkLogoutView
from auth_token.contrib.rest_framework_auth.views import (
    LoginAuthToken, LogoutAuthToken, MobileLoginAuthToken, MobileRegisterToken
)
from is_core.site import site as is_core_site

admin.site.login = AdminLoginView.as_view()
admin.site.logout = AdminLogoutView.as_view()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('is_core/', include(is_core_site.urls)),
    path('api/login/', LoginAuthToken.as_view()),
    path('api/logout/', LogoutAuthToken.as_view()),
    path('api/mobile-login/', MobileLoginAuthToken.as_view()),
    path('api/mobile-request-token/', MobileRegisterToken.as_view()),
    path('api/docs/login/', RESTFrameworkLoginView.as_view()),
    path('api/docs/logout/', RESTFrameworkLogoutView.as_view()),
    path('api/', SimpleAPI.as_view())
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
