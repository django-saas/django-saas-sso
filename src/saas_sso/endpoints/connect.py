from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import IntegrityError
from django.shortcuts import render

from .auth import LoginView, AuthorizedView
from ..models import UserIdentity


class ConnectRedirectView(LoginRequiredMixin, LoginView):
    redirect_url_name = 'saas_sso:connect'


class ConnectAuthorizedView(LoginRequiredMixin, AuthorizedView):
    def perform_authorize(self, request, **kwargs):
        provider = self._get_provider(**kwargs)
        token = provider.fetch_token(request)
        userinfo = provider.fetch_userinfo(request, token)
        try:
            strategy = kwargs['strategy']
            UserIdentity.objects.update_or_create(
                user=request.user,
                strategy=strategy,
                defaults={
                    'subject': userinfo['sub'],
                    'profile': userinfo,
                },
            )
            return self.get_success_response(**kwargs)
        except IntegrityError:
            error = {
                'title': 'Connection Error',
                'code': 400,
                'message': f'This {provider.name} account is already connected to another user.',
            }
            return render(request, 'saas/error.html', context={'error': error}, status=400)
