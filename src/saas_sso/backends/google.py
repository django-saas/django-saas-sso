from django.http import HttpRequest
from ._oauth2 import OAuth2Provider
from .types import OAuth2Token


class GoogleProvider(OAuth2Provider):
    name = 'Google'
    strategy = 'google'
    openid_configuration_endpoint = 'https://accounts.google.com/.well-known/openid-configuration'
    code_challenge_method = 'S256'
    scope = 'openid profile email'

    def fetch_userinfo(self, request: HttpRequest, token: OAuth2Token):
        id_token = token.pop('id_token', None)
        if id_token:
            claims = self.extract_id_token(request, id_token)
        else:
            resp = self.get(self.get_userinfo_endpoint(), token=token)
            claims = resp.json()

        # use email's username as preferred_username
        username = claims.get('preferred_username')
        if not username:
            username = claims['email'].split('@')[0]
            claims['preferred_username'] = username.lower()
        return claims
