from django.utils.translation import gettext_lazy as _
from saas_base.registry import perm_registry


# User Identities
perm_registry.register_permission(
    key='user.identities.view',
    label=_('View Identities'),
    module='User',
    description=_('List all sso identities'),
)
perm_registry.register_permission(
    key='user.identities.manage',
    label=_('Manage Identities'),
    module='User',
    description=_('Disconnect SSO identities'),
)
