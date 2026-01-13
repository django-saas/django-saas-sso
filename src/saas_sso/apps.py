from django.apps import AppConfig


class SingleSignOnConfig(AppConfig):
    name = 'saas_sso'
    verbose_name = 'SaaS SSO'

    def ready(self):
        import saas_sso.registry.default_perms  # noqa
