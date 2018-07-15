.. _contribution

Django-is-core
==============

If you wan to use ``django-auth-token`` with ``django-is-core`` you only need to go thought steps inside configuration
part. All other ``django-is-core`` settings changes are automatic.



Django-admin
============

You can use standard ``django-admin`` library with ``django-auth-token``. Configuration is little bit complicated.
Inside our URL config you must override standard admin login and logout views::

    from django.contrib import admin
    from django.urls import path

    from auth_token.contrib.admin.views import LoginView, LogoutView

    admin.site.login = AdminLoginView.as_view()
    admin.site.logout = AdminLogoutView.as_view()

    urlpatterns = [
        path('admin/', admin.site.urls),
    ]



Django-rest-framework
=====================

With ``django-rest-framework`` you must firstly update your settings::

    INSTALLED_APPS = (
        ...
        'auth_token',
        # REST framework
        'rest_framework',
        'auth_token.contrib.rest_framework_auth',
        ...
    )

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'auth_token.contrib.rest_framework_auth.authentication.AuthTokenAuthentication',
        ),
        'DEFAULT_PERMISSION_CLASSES': (
            'rest_framework.permissions.IsAuthenticated',
        )
    }


Next you can add login and logout views to your URL config::

    from django.urls import path

    from auth_token.contrib.rest_framework_auth.views import LoginAuthToken, LogoutAuthToken

    urlpatterns = [
        path('login/', LoginAuthToken.as_view()),
        path('logout/', LogoutAuthToken.as_view()),
    ]
