import json
import time
import requests
import functools
from joserfc import jwt
from joserfc.jwk import ECKey
from ._oauth2 import OAuth2Provider, MismatchStateError
from .types import OAuth2Token


class AppleProvider(OAuth2Provider):
    name = 'Apple'
    strategy = 'apple'
    token_endpoint_auth_method = 'client_secret_post'
    authorization_endpoint = 'https://appleid.apple.com/auth/authorize'
    token_endpoint = 'https://appleid.apple.com/auth/token'
    jwks_uri = 'https://appleid.apple.com/auth/keys'
    issuer = 'https://appleid.apple.com'
    scope = 'openid profile email'
    response_type = 'code id_token'
    response_mode = 'form_post'

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
            'iss': team_id,
            'iat': now,
            'exp': now + 600,  # 10 minutes expiry
            'aud': self.issuer,
            'sub': client_id,
        }
        return jwt.encode(headers, payload, self.private_key())

    def fetch_token(self, request) -> OAuth2Token:
        state = request.POST.get('state')
        if not state:
            raise MismatchStateError()

        if not request.session.get(f'_state:{state}'):
            raise MismatchStateError()

        cached_data = self.recover_cached_state(state)
        request.session.delete(f'_state:{state}')
        id_token = request.POST.get('id_token')
        external_user = request.POST.get('user')
        token: OAuth2Token = {
            '_external': external_user,
            'id_token': request.POST.get('id_token'),
        }
        if id_token:
            return token

        code = request.POST.get('code')
        client_secret = self.get_client_secret()
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': cached_data['redirect_uri'],
            'client_id': cached_data['client_id'],
            'client_secret': client_secret,
        }

        resp = requests.post(
            self.token_endpoint,
            data=data,
            timeout=5,
            headers=self.token_endpoint_headers,
        )
        resp.raise_for_status()
        token = resp.json()
        token['_external'] = external_user
        return token

    def fetch_userinfo(self, token: OAuth2Token):
        id_token = token.pop('id_token', None)
        claims_registry = jwt.JWTClaimsRegistry(
            leeway=100,
            iss={'essential': True, 'value': self.issuer},
            sub={'essential': True},
            email={'essential': True},
        )
        _tok = self.extract_id_token(id_token)
        claims_registry.validate(_tok.claims)
        claims = _tok.claims

        if token.get('_external'):
            external_data = json.loads(token['_external'])
            user_name = external_data.get('name')
            if user_name:
                if 'firstName' in user_name:
                    claims['given_name'] = user_name['firstName']
                if 'lastName' in user_name:
                    claims['family_name'] = user_name['lastName']
        return claims
