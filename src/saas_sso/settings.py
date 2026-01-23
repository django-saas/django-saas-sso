from __future__ import annotations

import typing
from django.core.signals import setting_changed
from saas_base.settings import BaseSettings

if typing.TYPE_CHECKING:
    from .backends import OAuth2Provider


class SSOSettings(BaseSettings):
    SETTINGS_KEY: str = 'SAAS_SSO'
    DEFAULT_SETTINGS = {
        'TRUST_EMAIL_VERIFIED': False,
        'AUTO_CREATE_USER': False,
        # AUTHORIZED_URL = 'https://example.com/authorized/{strategy}'
        'AUTHORIZED_URL': '',
        'AUTHORIZED_REDIRECT_URL': '',
        'PROVIDERS': [],
    }
    IMPORT_SETTINGS = [
        'PROVIDERS',
    ]

    @property
    def sso_providers(self) -> dict[str, 'OAuth2Provider']:
        return {provider.strategy: provider for provider in self.PROVIDERS}

    def get_sso_provider(self, strategy):
        return self.sso_providers.get(strategy)


sso_settings = SSOSettings()
setting_changed.connect(sso_settings.listen_setting_changed)
