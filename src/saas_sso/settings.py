from django.core.signals import setting_changed
from saas_base.settings import BaseSettings


class SSOSettings(BaseSettings):
    SETTINGS_KEY: str = 'SAAS_SSO'
    DEFAULT_SETTINGS = {
        'TRUST_EMAIL_VERIFIED': False,
        'PROVIDERS': [],
    }
    IMPORT_SETTINGS = [
        'PROVIDERS',
    ]

    @property
    def sso_providers(self):
        return {provider.strategy: provider for provider in self.PROVIDERS}

    def get_sso_provider(self, strategy):
        return self.sso_providers.get(strategy)


sso_settings = SSOSettings()
setting_changed.connect(sso_settings.listen_setting_changed)
