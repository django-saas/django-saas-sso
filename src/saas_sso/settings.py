from django.core.signals import setting_changed
from saas_base.settings import Settings

DEFAULTS = {
    'TRUST_EMAIL_VERIFIED': False,
    'PROVIDERS': [],
}


class SSOSettings(Settings):
    IMPORT_PROVIDERS = [
        'PROVIDERS',
    ]

    @property
    def sso_providers(self):
        return {provider.strategy: provider for provider in self.PROVIDERS}


sso_settings = SSOSettings('SAAS_SSO', defaults=DEFAULTS)
setting_changed.connect(sso_settings.listen_setting_changed)
