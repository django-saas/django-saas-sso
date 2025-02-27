import typing as t
import uuid
from django.views.generic import RedirectView, View
from django.http.response import Http404, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import render
from django.urls import reverse
from django.conf import settings
from django.db.utils import IntegrityError
from django.contrib.auth import get_user_model, login
from django.contrib.auth.models import AbstractUser
from saas_base.models import UserEmail
from saas_base.signals import after_signup_user, after_login_user
from ..models import UserIdentity
from ..backends import get_sso_provider, MismatchStateError
from ..types import UserInfo
from ..settings import sso_settings


class LoginView(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        next_url = self.request.GET.get("next")
        if next_url:
            self.request.session["next_url"] = next_url

        provider = _get_provider(kwargs["strategy"])
        redirect_uri = reverse("saas_sso:auth", kwargs=kwargs)
        return provider.create_authorization_url(self.request.build_absolute_uri(redirect_uri))


class AuthorizedView(View):
    def trust_email_verified_login(self, userinfo: UserInfo):
        try:
            user_email = UserEmail.objects.get_by_email(userinfo["email"])
            UserIdentity.objects.create(
                strategy=self.kwargs['strategy'],
                user_id=user_email.user_id,
                subject=userinfo["sub"],
                profile=userinfo,
            )
            return self.login_user(user_email.user)
        except UserEmail.DoesNotExist:
            return self.create_user_login(userinfo)

    def create_user_login(self, userinfo: UserInfo):
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

        UserIdentity.objects.create(
            strategy=self.kwargs['strategy'],
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
            request=self.request,
            strategy=self.kwargs['strategy'],
        )
        return self.login_user(user)

    def login_user(self, user: AbstractUser):
        login(self.request, user, 'django.contrib.auth.backends.ModelBackend')
        after_login_user.send(
            self.__class__,
            user=user,
            request=self.request,
            strategy=self.kwargs['strategy'],
        )
        next_url = self.request.session.get("next_url")
        if next_url:
            url_is_safe = url_has_allowed_host_and_scheme(
                url=next_url,
                allowed_hosts={self.request.get_host()},
                require_https=self.request.is_secure(),
            )
            if url_is_safe:
                return HttpResponseRedirect(next_url)
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
        try:
            identity = UserIdentity.objects.select_related('user').get(
                strategy=provider.strategy,
                subject=userinfo["sub"],
            )
            return self.login_user(identity.user)
        except UserIdentity.DoesNotExist:
            pass

        if userinfo["email_verified"] and sso_settings.TRUST_EMAIL_VERIFIED:
            return self.trust_email_verified_login(userinfo)
        return self.create_user_login(userinfo)


def _get_provider(strategy: str):
    provider = get_sso_provider(strategy)
    if provider is None:
        raise Http404()
    return provider
