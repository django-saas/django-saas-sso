import typing as t
from ._oauth2 import OAuth2Provider, OAuth2Auth, MismatchStateError
from .google import GoogleProvider
from .github import GitHubProvider
from ..settings import sso_settings


__all__ = [
    'OAuth2Provider', 'OAuth2Auth', 'MismatchStateError',
    'GoogleProvider', 'GitHubProvider',
    'get_sso_provider',
]


def get_sso_provider(strategy: str) -> t.Optional[OAuth2Provider]:
    return sso_settings.sso_providers.get(strategy)
