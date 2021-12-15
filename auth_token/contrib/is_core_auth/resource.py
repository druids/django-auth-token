from auth_token.utils import is_installed_security

if is_installed_security:
    from .auth_security.resource import AuthResource  # noqa: F401
else:
    from .default.resource import AuthResource  # noqa: F401
