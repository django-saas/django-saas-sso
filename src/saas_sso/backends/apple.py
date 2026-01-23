import json
import time
import functools

from django.http import HttpRequest
from joserfc import jwt
from joserfc.jwk import ECKey
from ._oauth2 import OAuth2Provider
from .types import OAuth2Token


class AppleProvider(OAuth2Provider):
    name = 'Apple'
    strategy = 'apple'
    token_endpoint_auth_method = 'client_secret_post'
    openid_configuration_endpoint = 'https://appleid.apple.com/.well-known/openid-configuration'
    scope = 'openid profile email'
    response_type = 'code id_token'
    response_mode = 'form_post'
    code_challenge_method = 'S256'

    @functools.cache
    def private_key(self):
        file_path = self.options['private_key_path']
        with open(file_path, 'rb') as f:
            return ECKey.import_key(f.read())

    def get_client_secret(self) -> str:
        # https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
        metadata = self.get_openid_configuration()
        client_id = self.get_client_id()
        team_id = self.options['team_id']
        key_id = self.options['key_id']
        headers = {'kid': key_id, 'alg': 'ES256'}
        now = int(time.time())
        payload = {
            'iss': team_id,
            'iat': now,
            'exp': now + 600,  # 10 minutes expiry
            'aud': metadata['issuer'],
            'sub': client_id,
        }
        return jwt.encode(headers, payload, self.private_key())

    def fetch_token(self, request: HttpRequest) -> OAuth2Token:
        cached_state = self.verify_cached_state(request)
        id_token = request.POST.get('id_token')
        external_user = request.POST.get('user')
        if id_token:
            token: OAuth2Token = {
                '_external': external_user,
                'id_token': id_token,
            }
            return token

        token = self._process_fetch_token(request, cached_state)
        token['_external'] = external_user
        return token

    def fetch_userinfo(self, request: HttpRequest, token: OAuth2Token):
        id_token = token.pop('id_token', None)
        claims = self.extract_id_token(request, id_token)

        if token.get('_external'):
            external_data = json.loads(token['_external'])
            user_name = external_data.get('name')
            if user_name:
                if 'firstName' in user_name:
                    claims['given_name'] = user_name['firstName']
                if 'lastName' in user_name:
                    claims['family_name'] = user_name['lastName']
        return claims
