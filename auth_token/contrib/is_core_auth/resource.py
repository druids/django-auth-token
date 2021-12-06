from auth_token.utils import is_installed_security

if is_installed_security:
    from .auth_security.resource import AuthResource
else:
    from .default.resource import AuthResource