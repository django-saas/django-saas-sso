from rest_framework.request import Request
from rest_framework.mixins import ListModelMixin, DestroyModelMixin
from saas_base.drf.views import AuthenticatedEndpoint
from saas_base.drf.filters import CurrentUserFilter
from saas_base.drf.decorators import resource_permission
from ..models import UserIdentity
from ..serializers import UserIdentitySerializer


class UserIdentityListEndpoint(ListModelMixin, AuthenticatedEndpoint):
    pagination_class = None
    queryset = UserIdentity.objects.all()
    filter_backends = [CurrentUserFilter]
    serializer_class = UserIdentitySerializer

    @resource_permission('user.identities.view')
    def get(self, request: Request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class UserIdentityItemEndpoint(DestroyModelMixin, AuthenticatedEndpoint):
    queryset = UserIdentity.objects.all()
    filter_backends = [CurrentUserFilter]
    serializer_class = UserIdentitySerializer

    @resource_permission('user.identities.manage')
    def delete(self, request: Request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)
