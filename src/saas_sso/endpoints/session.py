from django.core.cache import cache
from django.contrib.auth import login
from django.conf import settings
from rest_framework.exceptions import NotFound
from rest_framework.request import Request
from rest_framework.response import Response
from saas_base.drf.views import Endpoint
from saas_base.signals import after_signup_user
from saas_sso.auth.create_user import create_user_with_userinfo
from saas_sso.serializers import UsernameSerializer
from saas_sso.settings import sso_settings


class BaseSessionEndpoint(Endpoint):
    authentication_classes = []
    permission_classes = []

    def parse_cached_userinfo(self, request: Request):
        user_key = request.session.get('sso_userinfo')
        if not user_key:
            raise NotFound()
        userinfo = cache.get(f'sso_userinfo_{user_key}')
        if not userinfo:
            raise NotFound()
        strategy = user_key.split(':', 1)[0]
        return userinfo, strategy


class SessionUserInfoEndpoint(BaseSessionEndpoint):
    """This endpoint returns the user info of the current session."""

    def get(self, request: Request):
        userinfo, _ = self.parse_cached_userinfo(request)
        return Response(userinfo)


class SessionCreateUserEndpoint(BaseSessionEndpoint):
    """Create a user with a username, other userinfo is cached in the session."""

    serializer_class = UsernameSerializer
    redirect_url = settings.LOGIN_REDIRECT_URL

    def post(self, request: Request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        userinfo, strategy = self.parse_cached_userinfo(request)
        username = serializer.validated_data['username']
        user = create_user_with_userinfo(username, strategy, userinfo)
        after_signup_user.send(
            self.__class__,
            user=user,
            request=request,
            strategy=strategy,
        )
        provider = sso_settings.get_sso_provider(strategy)
        backend = f'{provider.__module__}.{provider.__class__.__name__}'
        login(request._request, user, backend=backend)
        return Response({'next': self.redirect_url})
