import time
import functools
from joserfc import jwt
from joserfc.jwk import ECKey
from ._oauth2 import OAuth2Provider
from .types import OAuth2Token


class AppleProvider(OAuth2Provider):
    strategy = 'apple'
    token_endpoint_auth_method = "client_secret_post"
    authorization_endpoint = 'https://appleid.apple.com/auth/authorize'
    token_endpoint = 'https://appleid.apple.com/auth/token'
    jwks_uri = 'https://appleid.apple.com/auth/keys'
    issuer = 'https://appleid.apple.com'
    scope = 'openid profile email'

    @functools.cache
    def private_key(self):
        file_path = self.options['private_key_path']
        with open(file_path, 'rb') as f:
            return ECKey.import_key(f.read())

    def get_client_secret(self) -> str:
        # https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
        client_id = self.get_client_id()
        team_id = self.options['team_id']
        key_id = self.options['key_id']
        headers = {'kid': key_id, 'alg': 'ES256'}
        now = int(time.time())
        payload = {
            "iss": team_id,
            "iat": now,
            "exp": now + 600,  # 10 minutes expiry
            "aud": self.issuer,
            "sub": client_id,
        }
        return jwt.encode(headers, payload, self.private_key)

    def fetch_userinfo(self, token: OAuth2Token):
        id_token = token.pop("id_token", None)
        claims_registry = jwt.JWTClaimsRegistry(
            leeway=100,
            iss={"essential": True, "value": self.issuer},
            sub={"essential": True},
            email={"essential": True},
        )
        _tok = self.extract_id_token(id_token)
        claims_registry.validate(_tok.claims)
        claims = _tok.claims
        return claims
