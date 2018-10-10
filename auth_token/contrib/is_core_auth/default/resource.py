from django.utils.translation import ugettext

from pyston.response import RESTErrorResponse, RESTNoContentResponse
from pyston.exception import RESTException

from is_core.auth.permissions import AllowAny
from is_core.rest.resource import RESTResource

from auth_token.contrib.is_core_auth.forms import TokenAuthenticationSmartForm
from auth_token.utils import login, logout


class AuthResource(RESTResource):

    permission = AllowAny()

    csrf_exempt = True

    allowed_methods = ('post', 'delete')
    form_class = TokenAuthenticationSmartForm
    allowed_cookie = False
    allowed_header = True

    def _sucessful_login(self, request):
        pass

    def _login(self, user, expiration, form):
        login(self.request, user, expiration, allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header)

    def _unsucessful_login(self, request):
        pass

    def get_form_kwargs(self):
        return {'data': self.get_dict_data(), 'request': self.request}

    def get_form_class(self):
        return self.form_class

    def post(self):
        if not self.request.data:
            raise RESTException(ugettext('Missing data'))
        form = self.get_form_class()(**self.get_form_kwargs())

        errors = form.is_invalid()
        if errors:
            self._unsucessful_login(self.request)
            return RESTErrorResponse(errors)

        self._sucessful_login(self.request)
        self._login(form.get_user(), not form.is_permanent(), form)
        return {'token': self.request.token.key, 'user': form.get_user()}

    def delete(self):
        if self.request.user.is_authenticated:
            logout(self.request)
        return RESTNoContentResponse()

    @classmethod
    def __init_core__(cls, core, pattern):
        cls.core = core
        cls.pattern = pattern

    def has_delete_permission(self, **kwargs):
        return (
            self.request.user.is_authenticated and super().has_delete_permission(**kwargs)
        )
