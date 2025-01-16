from rest_framework.request import Request
from rest_framework.mixins import ListModelMixin
from saas_base.drf.views import Endpoint
from ..models import UserIdentity
from ..serializers import UserIdentitySerializer


class UserIdentityListEndpoint(ListModelMixin, Endpoint):
    resource_scopes = ["user:read"]
    pagination_class = None
    serializer_class = UserIdentitySerializer

    def get_queryset(self):
        return UserIdentity.objects.filter(user=self.request.user).all()

    def get(self, request: Request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
