from django.views.generic.base import RedirectView

from is_core.generic_views.mixins import DefaultCoreViewMixin, CoreGetObjViewMixin

from auth_token.config import settings
from auth_token.contrib.common.views import LoginView as _LoginView, LogoutView as _LogoutView
from auth_token.utils import takeover


class LoginView(_LoginView):

    template_name = 'is_core/login.html'


class LogoutView(_LogoutView):

    template_name = 'is_core/logged_out.html'


class UserTakeover(CoreGetObjViewMixin, DefaultCoreViewMixin, RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        return settings.TAKEOVER_REDIRECT_URL

    def get(self, request, *args, **kwargs):
        user = self.get_obj()
        takeover(request, user)
        return super().get(request, *args, **kwargs)
