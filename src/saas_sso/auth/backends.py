import uuid
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.utils import IntegrityError
from saas_base.models import UserEmail
from saas_base.signals import after_signup_user
from ..models import UserIdentity
from ..settings import sso_settings
from ..types import UserInfo

__all__ = ["UserIdentityBackend"]

UserModel = get_user_model()


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
                subject=userinfo["sub"],
            )
            return identity.user
        except UserIdentity.DoesNotExist:
            pass

        if userinfo["email_verified"] and sso_settings.TRUST_EMAIL_VERIFIED:
            return self.connect_or_create_user(request, strategy, userinfo)
        return self.create_user_identity(request, strategy, userinfo)

    def connect_or_create_user(self, request, strategy: str, userinfo: UserInfo):
        try:
            user_email = UserEmail.objects.get_by_email(userinfo["email"])
            UserIdentity.objects.create(
                strategy=strategy,
                user_id=user_email.user_id,
                subject=userinfo["sub"],
                profile=userinfo,
            )
            return user_email.user
        except UserEmail.DoesNotExist:
            return self.create_user_identity(request, strategy, userinfo)

    def create_user_identity(self, request, strategy: str, userinfo: UserInfo):
        username = userinfo.get("preferred_username")
        try:
            user = UserModel.objects.create_user(
                username,
                userinfo["email"],
                first_name=userinfo.get("given_name"),
                last_name=userinfo.get("family_name"),
            )
        except IntegrityError:
            user = UserModel.objects.create_user(
                uuid.uuid4().hex,
                userinfo["email"],
                first_name=userinfo.get("given_name"),
                last_name=userinfo.get("family_name"),
            )

        UserIdentity.objects.create(
            strategy=strategy,
            user=user,
            subject=userinfo["sub"],
            profile=userinfo,
        )

        # auto add user email
        if userinfo["email_verified"]:
            UserEmail.objects.create(
                user_id=user.pk,
                email=userinfo["email"],
                verified=True,
                primary=True,
            )

        after_signup_user.send(
            self.__class__,
            user=user,
            request=request,
            strategy=strategy,
        )
        return user
