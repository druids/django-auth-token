from django.utils.translation import ugettext

from pyston.response import RestErrorResponse, RestNoContentResponse
from pyston.exception import RestException

from is_core.auth.permissions import AllowAny
from is_core.rest.resource import CoreResource

from auth_token.contrib.is_core_auth.forms import TokenAuthenticationSmartForm
from auth_token.utils import login, logout


class AuthResource(CoreResource):

    permission = AllowAny()

    csrf_exempt = True

    allowed_methods = ('post', 'delete')
    form_class = TokenAuthenticationSmartForm
    allowed_cookie = False
    allowed_header = True

    def _sucessful_login(self, request):
        pass

    def _login(self, user, permanent, form, two_factor_login=False, auth_slug=None):
        login(
            self.request,
            user,
            auth_slug=auth_slug,
            preserve_cookie=permanent,
            allowed_cookie=self.allowed_cookie,
            allowed_header=self.allowed_header,
            two_factor_login=two_factor_login
        )

    def _unsucessful_login(self, request):
        pass

    def get_form_kwargs(self):
        return {'data': self.get_dict_data(), 'request': self.request}

    def get_form_class(self):
        return self.form_class

    def post(self):
        if not self.request.data:
            raise RestException(ugettext('Missing data'))
        form = self.get_form_class()(**self.get_form_kwargs())

        errors = form.is_invalid()
        if errors:
            self._unsucessful_login(self.request)
            return RestErrorResponse(errors)

        self._sucessful_login(self.request)
        self._login(form.get_user(), not form.is_permanent(), form)
        return {'token': self.request.token.secret_key, 'user': form.get_user()}

    def delete(self):
        if self.request.user.is_authenticated:
            logout(self.request)
        return RestNoContentResponse()

    @classmethod
    def __init_core__(cls, core, pattern):
        cls.core = core
        cls.pattern = pattern

    def has_delete_permission(self, **kwargs):
        return (
            self.request.user.is_authenticated and super().has_delete_permission(**kwargs)
        )
