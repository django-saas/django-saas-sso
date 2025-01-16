import typing as t
import uuid
from django.views.generic import RedirectView, View
from django.http.response import Http404, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.conf import settings
from django.db.utils import IntegrityError
from django.contrib.auth import get_user_model, login
from django.contrib.auth.models import AbstractUser
from saas_base.models import UserEmail
from saas_base.signals import after_signup_user, after_login_user
from ..models import UserIdentity
from ..backends import get_sso_provider, OAuth2Provider, MismatchStateError
from ..types import UserInfo


class LoginView(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        next_url = self.request.GET.get("next")
        if next_url:
            self.request.session["next_url"] = next_url

        provider = _get_provider(kwargs["strategy"])
        redirect_uri = reverse("saas_sso:auth", kwargs=kwargs)
        return provider.create_authorization_url(self.request.build_absolute_uri(redirect_uri))


class AuthorizedView(View):
    @staticmethod
    def filter_user_by_email(email: str):
        try:
            user_email = UserEmail.objects.get_by_email(email)
        except UserEmail.DoesNotExist:
            return None
        return user_email.user_id

    @staticmethod
    def create_user(userinfo: UserInfo):
        username = userinfo.get("preferred_username")
        cls: t.Type[AbstractUser] = get_user_model()
        try:
            user = cls.objects.create_user(
                username,
                userinfo["email"],
                first_name=userinfo.get("given_name"),
                last_name=userinfo.get("family_name"),
            )
        except IntegrityError:
            user = cls.objects.create_user(
                uuid.uuid4().hex,
                userinfo["email"],
                first_name=userinfo.get("given_name"),
                last_name=userinfo.get("family_name"),
            )
        # auto add user email
        if userinfo["email_verified"]:
            UserEmail.objects.create(
                user_id=user.pk,
                email=userinfo["email"],
                verified=True,
                primary=True,
            )
        return user

    @staticmethod
    def create_identity(provider: OAuth2Provider, user_id: int, userinfo: UserInfo):
        return UserIdentity.objects.create(
            strategy=provider.strategy,
            user_id=user_id,
            subject=userinfo["sub"],
            profile=userinfo,
        )

    def login_user(self, user: AbstractUser):
        login(self.request, user, 'django.contrib.auth.backends.ModelBackend')
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)

    def get(self, request, *args, **kwargs):
        provider = _get_provider(kwargs["strategy"])
        try:
            token = provider.fetch_token(request)
        except MismatchStateError:
            error = {
                "title": "OAuth Error",
                "code": 400,
                "message": "OAuth parameter state does not match."
            }
            return render(request, "saas/error.html", context={"error": error}, status=400)
        userinfo = provider.fetch_userinfo(token)
        if userinfo["email_verified"]:
            user_id = self.filter_user_by_email(userinfo["email"])
            if user_id:
                identity = self.create_identity(provider, user_id, userinfo)
                user = identity.user
                after_login_user.send(
                    self.__class__,
                    user=user,
                    request=request,
                    strategy=provider.strategy,
                )
                return self.login_user(user)

        user = self.create_user(userinfo)
        after_signup_user.send(
            self.__class__,
            user=user,
            request=request,
            strategy=provider.strategy,
        )
        self.create_identity(provider, user.pk, userinfo)
        return self.login_user(user)


def _get_provider(strategy: str):
    provider = get_sso_provider(strategy)
    if provider is None:
        raise Http404()
    return provider
