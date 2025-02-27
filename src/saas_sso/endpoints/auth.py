import typing as t
import uuid
from django.views.generic import RedirectView, View
from django.http.response import Http404, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import render
from django.urls import reverse
from django.conf import settings
from django.db.utils import IntegrityError
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.models import AbstractUser
from saas_base.models import UserEmail
from saas_base.signals import after_signup_user, after_login_user
from ..models import UserIdentity
from ..backends import MismatchStateError
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

        user = authenticate(request, strategy=kwargs["strategy"], token=token)
        login(request, user)

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


def _get_provider(strategy: str):
    provider = sso_settings.get_sso_provider(strategy)
    if provider is None:
        raise Http404()
    return provider
