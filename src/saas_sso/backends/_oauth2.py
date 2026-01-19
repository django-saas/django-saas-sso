import typing as t
import uuid
import requests
from abc import ABCMeta, abstractmethod
from urllib import parse as urlparse
from requests import PreparedRequest
from requests.auth import AuthBase
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.util import to_bytes, to_str
from django.core.cache import cache
from saas_base.secure import resolve_secret
from .types import OAuth2Token, Placement, UserInfo

__all__ = ['OAuth2Provider', 'OAuth2Auth', 'MismatchStateError']

CACHE_PREFIX = 'saas:oauth2state:'


class MismatchStateError(Exception):
    pass


class OAuth2Auth(AuthBase):
    def __init__(self, access_token: str, placement: Placement = 'header') -> None:
        self.access_token = access_token
        self.placement = placement

    def add_to_header(self, headers) -> None:
        headers['Authorization'] = f'Bearer {self.access_token}'

    def add_to_uri(self, uri: str) -> str:
        return add_params_to_uri(uri, [('access_token', self.access_token)])

    def add_to_body(self, body: t.Optional[str] = None) -> str:
        if body is None:
            body = ''
        return add_params_to_qs(body, [('access_token', self.access_token)])

    def __call__(self, req: PreparedRequest):
        if self.placement == 'header':
            self.add_to_header(req.headers)
        elif self.placement == 'uri':
            req.url = self.add_to_uri(req.url)
        elif self.placement == 'body':
            req.body = self.add_to_body(req.body)
        return req


class OAuth2Provider(metaclass=ABCMeta):
    TYPE: str = 'oauth2'
    STATE_EXPIRES_IN: int = 300

    token_endpoint_auth_method: str = 'client_secret_basic'
    token_endpoint_headers: t.Dict[str, str] = {'Accept': 'application/json'}
    bearer_token_placement: Placement = 'header'

    name: str = 'OAuth'
    strategy: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    scope: str
    response_type: str = 'code'
    response_mode: t.Literal['query', 'form_post'] = 'query'

    # jwks
    jwks_uri: t.ClassVar[str]
    jwks: t.ClassVar[KeySet] = KeySet([])

    def __init__(self, **options):
        self.options = options

    def get_client_id(self) -> str:
        client_id = self.options.get('client_id', f'secret:{self.strategy}_client_id')
        return resolve_secret(client_id)

    def get_client_secret(self) -> str:
        client_secret = self.options.get('client_secret', f'secret:{self.strategy}_client_secret')
        return resolve_secret(client_secret)

    @classmethod
    def fetch_key_set(cls, force: bool = False) -> KeySet:
        if cls.jwks.keys and not force:
            return cls.jwks
        resp = requests.get(cls.jwks_uri, timeout=5)
        data = resp.json()
        jwks = KeySet.import_key_set(data)
        cls.jwks = jwks
        return jwks

    def create_authorization_url(self, request, redirect_uri: str) -> str:
        client_id = self.get_client_id()
        scope = self.options.get('scope')
        if not scope:
            scope = self.scope

        state = uuid.uuid4().hex
        absolute_uri = request.build_absolute_uri(redirect_uri)
        params = [
            ('response_type', self.response_type),
            ('client_id', client_id),
            ('redirect_uri', absolute_uri),
            ('scope', scope),
            ('state', state),
        ]
        if self.response_mode == 'form_post':
            params.append(('response_mode', 'form_post'))
        cache.set(
            CACHE_PREFIX + state,
            {'client_id': client_id, 'redirect_uri': absolute_uri},
            timeout=self.STATE_EXPIRES_IN,
        )
        request.session[f'_state:{state}'] = '1'
        return add_params_to_uri(self.authorization_endpoint, params)

    def request(self, method: str, url: str, token: OAuth2Token, params=None, data=None, json=None, headers=None):
        auth = OAuth2Auth(token['access_token'], self.bearer_token_placement)
        return requests.request(
            method,
            url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            auth=auth,
            timeout=5,
        )

    def get(self, url: str, token: OAuth2Token, params=None, headers=None):
        return self.request('GET', url, token, params=params, headers=headers)

    def recover_cached_state(self, state: str):
        cached_data = cache.get(CACHE_PREFIX + state)
        if not cached_data:
            raise MismatchStateError()
        cache.delete(CACHE_PREFIX + state)
        return cached_data

    def fetch_token(self, request) -> OAuth2Token:
        state = request.GET.get('state')
        if not state:
            raise MismatchStateError()

        if not request.session.get(f'_state:{state}'):
            raise MismatchStateError()
        request.session.delete(f'_state:{state}')

        cached_data = self.recover_cached_state(state)
        code = request.GET.get('code')
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': cached_data['redirect_uri'],
        }
        if self.token_endpoint_auth_method == 'client_secret_basic':
            auth = (cached_data['client_id'], self.get_client_secret())
        else:
            auth = None
            data['client_id'] = cached_data['client_id']
            data['client_secret'] = self.get_client_secret()

        resp = requests.post(
            self.token_endpoint,
            data=data,
            auth=auth,
            timeout=5,
            headers=self.token_endpoint_headers,
        )
        resp.raise_for_status()
        return resp.json()

    def extract_id_token(self, id_token: str) -> jwt.Token:
        keys = self.fetch_key_set()
        try:
            return jwt.decode(id_token, keys)
        except ValueError:
            keys = self.fetch_key_set(force=True)
            return jwt.decode(id_token, keys)

    @abstractmethod
    def fetch_userinfo(self, token: OAuth2Token) -> UserInfo:
        pass


def url_encode(params: t.Sequence[t.Tuple[t.Any, t.Any]]) -> str:
    encoded = []
    for k, v in params:
        encoded.append((to_bytes(k), to_bytes(v)))
    return to_str(urlparse.urlencode(encoded))


def add_params_to_qs(query: str, params: t.Sequence[t.Tuple[str, str]]) -> str:
    """Extend a query with a list of two-tuples."""
    qs: t.List[t.Tuple[str, str]] = urlparse.parse_qsl(query, keep_blank_values=True)
    qs.extend(params)
    return url_encode(qs)


def add_params_to_uri(uri: str, params: t.Sequence[t.Tuple[str, str]], fragment: bool = False) -> str:
    """Add a list of two-tuples to the uri query components."""
    sch, net, path, par, query, fra = urlparse.urlparse(uri)
    if fragment:
        fra = add_params_to_qs(fra, params)
    else:
        query = add_params_to_qs(query, params)
    return urlparse.urlunparse((sch, net, path, par, query, fra))
