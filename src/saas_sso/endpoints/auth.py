from django.views.generic import RedirectView, View
from django.http.response import Http404, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import render
from django.urls import reverse
from django.conf import settings
from django.contrib.auth import authenticate, login
from saas_base.signals import after_login_user
from ..backends import MismatchStateError
from ..settings import sso_settings


class LoginView(RedirectView):
    redirect_url_name = 'saas_sso:auth'

    def get_authorization_redirect_url(self, **kwargs):
        if sso_settings.AUTHORIZATION_REDIRECT_URL:
            return sso_settings.AUTHORIZATION_REDIRECT_URL.format(**kwargs)
        return reverse(self.redirect_url_name, kwargs=kwargs)

    def get_redirect_url(self, *args, **kwargs):
        next_url = self.request.GET.get('next')
        if next_url:
            self.request.session['next_url'] = next_url

        provider = _get_provider(kwargs['strategy'])
        redirect_uri = self.get_authorization_redirect_url(**kwargs)
        return provider.create_authorization_url(self.request, redirect_uri)


class AuthorizedView(View):
    def get(self, request, *args, **kwargs):
        return self._perform_request(request, **kwargs)

    def post(self, request, *args, **kwargs):
        return self._perform_request(request, **kwargs)

    def _perform_request(self, request, **kwargs):
        try:
            return self.perform_authorize(request, **kwargs)
        except MismatchStateError:
            error = {'title': 'OAuth Error', 'code': 400, 'message': 'OAuth parameter state does not match.'}
            return render(request, 'saas/error.html', context={'error': error}, status=400)

    def _get_provider(self, **kwargs):
        return _get_provider(kwargs['strategy'])

    def get_redirect_url(self):
        if sso_settings.AUTHORIZED_REDIRECT_URL:
            return sso_settings.AUTHORIZED_REDIRECT_URL
        return settings.LOGIN_REDIRECT_URL

    def get_success_response(self, request):
        next_url = self.request.session.get('next_url')
        if next_url:
            url_is_safe = url_has_allowed_host_and_scheme(
                url=next_url,
                allowed_hosts={self.request.get_host()},
                require_https=self.request.is_secure(),
            )
            if url_is_safe:
                return HttpResponseRedirect(next_url)
        return HttpResponseRedirect(self.get_redirect_url())

    def perform_authorize(self, request, **kwargs):
        provider = self._get_provider(**kwargs)
        token = provider.fetch_token(request)
        user = authenticate(request, strategy=kwargs['strategy'], token=token)
        if user:
            login(request, user)
            after_login_user.send(
                self.__class__,
                user=user,
                request=self.request,
                strategy=self.kwargs['strategy'],
            )
        return self.get_success_response(request)


def _get_provider(strategy: str):
    provider = sso_settings.get_sso_provider(strategy)
    if provider is None:
        raise Http404()
    return provider
