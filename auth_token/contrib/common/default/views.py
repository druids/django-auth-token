from django.contrib.auth.views import LoginView, LogoutView
from django.utils.decorators import method_decorator
from django.http import HttpResponseRedirect
from django.views.decorators.cache import never_cache

from auth_token.contrib.common.forms import TokenAuthenticationForm
from auth_token.utils import login, logout


class TokenLoginView(LoginView):

    form_class = TokenAuthenticationForm
    allowed_cookie = True
    allowed_header = False

    def get(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            return HttpResponseRedirect(self.get_success_url())
        else:
            return super().get(request, *args, **kwargs)

    def _login(self, user, preserve_cookie, form):
        login(
            self.request, user, preserve_cookie=preserve_cookie,
            allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header
        )

    def form_valid(self, form):
        """
        The user has provided valid credentials (this was checked in AuthenticationForm.is_valid()). So now we
        can check the test cookie stuff and log him in.
        """
        self._login(form.get_user(), not form.is_permanent(), form)
        return HttpResponseRedirect(self.get_success_url())


class TokenLogoutView(LogoutView):

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        logout(request)
        next_page = self.get_next_page()
        if next_page:
            # Redirect to this page until the session has been cleared.
            return HttpResponseRedirect(next_page)
        return super(LogoutView, self).dispatch(request, *args, **kwargs)


class InputLogMixin:

    def log_successful_request(self):
        pass

    def log_unsuccessful_request(self):
        pass
