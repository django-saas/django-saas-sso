from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import IntegrityError
from django.shortcuts import render

from .auth import LoginView, AuthorizedView
from ..models import UserIdentity
from ..settings import sso_settings


class ConnectRedirectView(LoginRequiredMixin, LoginView):
    redirect_url_name = 'saas_sso:connect'


class ConnectAuthorizedView(LoginRequiredMixin, AuthorizedView):
    def authorize(self, request, token, **kwargs):
        strategy = kwargs['strategy']
        provider = sso_settings.get_sso_provider(strategy)
        userinfo = provider.fetch_userinfo(token)
        try:
            UserIdentity.objects.update_or_create(
                user=request.user,
                strategy=strategy,
                defaults={
                    'subject': userinfo["sub"],
                    'profile': userinfo,
                }
            )
        except IntegrityError:
            error = {
                "title": "Connection Error",
                "code": 400,
                "message": f"This {provider.name} account is already connected to another user."
            }
            return render(request, "saas/error.html", context={"error": error}, status=400)
