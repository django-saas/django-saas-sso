import requests
from joserfc.jwt import JWTClaimsRegistry
from ._oauth2 import OAuth2Provider
from .types import OAuth2Token


class GoogleProvider(OAuth2Provider):
    strategy = 'google'
    authorization_endpoint = 'https://accounts.google.com/o/oauth2/v2/auth'
    token_endpoint = 'https://oauth2.googleapis.com/token'
    userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo'
    jwks_uri = 'https://www.googleapis.com/oauth2/v3/certs'
    scope = 'openid profile email'

    def fetch_userinfo(self, token: OAuth2Token):
        id_token = token.pop("id_token", None)
        if id_token:
            claims_registry = JWTClaimsRegistry(
                leeway=100,
                iss={"essential": True},
                sub={"essential": True},
                email={"essential": True},
            )
            _tok = self.extract_id_token(id_token)
            claims_registry.validate(_tok.claims)
            claims = _tok.claims
        else:
            resp = requests.get(self.userinfo_endpoint)
            claims = resp.json()

        # use email's username as preferred_username
        username = claims.get('preferred_username')
        if not username:
            username = claims['email'].split('@')[0]
            claims['preferred_username'] = username.lower()
        return claims
