from django.conf import settings
from django.contrib import admin
from django.urls import path
from django.conf.urls import include

from auth_token.contrib.admin.views import LoginView as AdminLoginView, LogoutView as AdminLogoutView
from auth_token.contrib.rest_framework_auth.views import (
    LoginView as RESTFrameworkLoginView, LogoutView as RESTFrameworkLogoutView, LoginAuthToken, LogoutAuthToken
)

from is_core.site import site as is_core_site

from app.resource import SimpleAPI


admin.site.login = AdminLoginView.as_view()
admin.site.logout = AdminLogoutView.as_view()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('is_core/', include(is_core_site.urls)),
    path('api/login/', LoginAuthToken.as_view()),
    path('api/logout/', LogoutAuthToken.as_view()),
    path('api/docs/login/', RESTFrameworkLoginView.as_view()),
    path('api/docs/logout/', RESTFrameworkLogoutView.as_view()),
    path('api/', SimpleAPI.as_view())
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
