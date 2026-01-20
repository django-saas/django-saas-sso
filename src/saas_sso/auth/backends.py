import uuid
from django.contrib.auth.backends import ModelBackend
from django.core.cache import cache
from saas_base.identity.models import UserEmail
from saas_base.signals import after_signup_user
from saas_sso.models import UserIdentity
from saas_sso.settings import sso_settings
from saas_sso.types import UserInfo
from .create_user import create_user_with_userinfo

__all__ = ['UserIdentityBackend']


class UserIdentityBackend(ModelBackend):
    def authenticate(self, request, strategy=None, token=None, **kwargs):
        if strategy is None or token is None:
            return

        provider = sso_settings.get_sso_provider(strategy)
        if provider is None:
            return

        userinfo = provider.fetch_userinfo(token)
        try:
            identity = UserIdentity.objects.select_related('user').get(
                strategy=provider.strategy,
                subject=userinfo['sub'],
            )
            return identity.user
        except UserIdentity.DoesNotExist:
            pass

        if userinfo['email_verified'] and sso_settings.TRUST_EMAIL_VERIFIED:
            user = self._find_related_user(request, strategy, userinfo)
            if user:
                return user

        if sso_settings.AUTO_CREATE_USER:
            return self._create_user(request, strategy, userinfo)

        self._save_userinfo(request, strategy, userinfo)

    def _find_related_user(self, request, strategy: str, userinfo: UserInfo):
        try:
            user_email = UserEmail.objects.get_by_email(userinfo['email'])
            UserIdentity.objects.create(
                strategy=strategy,
                user_id=user_email.user_id,
                subject=userinfo['sub'],
                profile=userinfo,
            )
            return user_email.user
        except UserEmail.DoesNotExist:
            return None

    def _save_userinfo(self, request, strategy: str, userinfo: UserInfo):
        # save userinfo for later
        user_key = f'{strategy}:{userinfo["sub"]}'
        cache_key = f'sso_userinfo_{user_key}'
        request.session['sso_userinfo'] = user_key
        cache.set(cache_key, userinfo, 600)

    def _create_user(self, request, strategy: str, userinfo: UserInfo):
        username = userinfo.get('preferred_username')
        if not username:
            username = uuid.uuid4().hex

        user = create_user_with_userinfo(username, strategy, userinfo)
        after_signup_user.send(
            self.__class__,
            user=user,
            request=request,
            strategy=strategy,
        )
        return user
