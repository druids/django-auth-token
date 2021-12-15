import warnings

from django import forms
from django.utils.translation import ugettext, ugettext_lazy as _
from django.contrib.auth import authenticate, get_user_model

from auth_token.config import settings


class AuthenticationMixin:
    """
    Base class for authenticating users. Extend this to get a form that accepts
    username/password logins.
    """
    username_field_name = 'username'

    error_messages = {
        'invalid_login': _('Please enter a correct %(username)s and password. '
                           'Note that both fields may be case-sensitive.'),
        'inactive': _('This account is inactive.'),
    }

    def __init__(self, request, *args, **kwargs):
        """
        The 'request' parameter is set for custom auth use by subclasses.
        The form data comes in via the standard 'data' kwarg.
        """
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

        self.init_username_field()
        self.init_password_field()

    def init_username_field(self):
        user_model = self.get_user_model()
        self.username_field = user_model._meta.get_field(user_model.USERNAME_FIELD)
        self.fields[self.username_field_name] = forms.CharField(max_length=254)
        if self.fields[self.username_field_name].label is None:
            self.fields[self.username_field_name].label = self.username_field.verbose_name

    def init_password_field(self):
        self.fields['password'] = forms.CharField(label=ugettext('Password'), widget=forms.PasswordInput)

    def get_user_model(self):
        return get_user_model()

    def password_auth_clean(self):
        username = self.cleaned_data.get(self.username_field_name)
        password = self.cleaned_data.get('password')
        if username and password:
            self.user_cache = authenticate(username=username, password=password)
            if self.user_cache is None:
                raise forms.ValidationError(
                    self.error_messages['invalid_login'],
                    code='invalid_login',
                    params={self.username_field_name: self.username_field.verbose_name},
                )
            elif not self.user_cache.is_active:
                raise forms.ValidationError(
                    self.error_messages['inactive'],
                    code='inactive',
                )
        return self.cleaned_data

    def check_for_test_cookie(self):
        warnings.warn('check_for_test_cookie is deprecated; ensure your login '
                      'view is CSRF-protected.', DeprecationWarning)

    def get_user_id(self):
        if self.user_cache:
            return self.user_cache.pk
        return None

    def get_user(self):
        return self.user_cache


class AuthenticationCleanMixin:

    def clean(self):
        return self.password_auth_clean()


class TokenAuthenticationMixin(AuthenticationMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if settings.FORM_COOKIE_PERMANENT:
            self.fields['permanent'] = forms.BooleanField(label=_('Remember user'), required=False)

    def is_permanent(self):
        return self.cleaned_data.get('permanent', False)


class TokenAuthenticationForm(TokenAuthenticationMixin, AuthenticationCleanMixin, forms.Form):
    pass
