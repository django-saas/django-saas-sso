import typing as t
import uuid
import requests
from abc import ABCMeta, abstractmethod
from requests import PreparedRequest
from requests.auth import AuthBase
from joserfc import jwt
from joserfc.jwk import KeySet
from django.core.cache import cache
from ._util import add_params_to_qs, add_params_to_uri
from .types import OAuth2Token, OAuth2Options, Placement, UserInfo

__all__ = ["OAuth2Provider", "OAuth2Auth", "MismatchStateError"]

CACHE_PREFIX = "saas:oauth2state:"


class MismatchStateError(Exception):
    pass


class OAuth2Auth(AuthBase):
    def __init__(self, access_token: str, placement: Placement = "header") -> None:
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
        if self.placement == "header":
            self.add_to_header(req.headers)
        elif self.placement == "uri":
            req.url = self.add_to_uri(req.url)
        elif self.placement == "body":
            req.body = self.add_to_body(req.body)
        return req


class OAuth2Provider(metaclass=ABCMeta):
    TYPE: str = "oauth2"
    STATE_EXPIRES_IN: int = 300

    token_endpoint_auth_method: str = "client_secret_basic"
    token_endpoint_headers: t.Dict[str, str] = {"Accept": "application/json"}
    bearer_token_placement: Placement = "header"

    strategy: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    scope: str

    # jwks
    jwks_uri: t.ClassVar[str]
    jwks: t.ClassVar[KeySet] = KeySet([])

    def __init__(self, **options):
        self.options: OAuth2Options = options

    @classmethod
    def fetch_key_set(cls, force: bool = False) -> KeySet:
        if cls.jwks.keys and not force:
            return cls.jwks
        resp = requests.get(cls.jwks_uri, timeout=5)
        data = resp.json()
        jwks = KeySet.import_key_set(data)
        cls.jwks = jwks
        return jwks

    def create_authorization_url(self, redirect_uri: str) -> str:
        client_id = self.options["client_id"]
        scope = self.options.get("scope")
        if not scope:
            scope = self.scope

        state = uuid.uuid4().hex
        params = [
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", scope),
            ("state", state),
        ]
        client_secret = self.options["client_secret"]
        cache.set(
            CACHE_PREFIX + state,
            {"client_secret": client_secret, **dict(params)},
            timeout=self.STATE_EXPIRES_IN,
        )
        return add_params_to_uri(self.authorization_endpoint, params)

    def request(self, method: str, url: str, token: OAuth2Token, params=None, data=None, json=None, headers=None):
        auth = OAuth2Auth(token['access_token'], self.bearer_token_placement)
        return requests.request(
            method, url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            auth=auth,
            timeout=5,
        )

    def get(self, url: str, token: OAuth2Token, params=None, headers=None):
        return self.request("GET", url, token, params=params, headers=headers)

    def fetch_token(self, request) -> OAuth2Token:
        state: str = request.GET["state"]
        params = cache.get(CACHE_PREFIX + state)
        if not params:
            raise MismatchStateError()

        code: str = request.GET["code"]
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
        }
        if self.token_endpoint_auth_method == "client_secret_basic":
            auth = (params["client_id"], params["client_secret"])
        else:
            auth = None
            data["client_id"] = params["client_id"]
            data["client_secret"] = params["client_secret"]

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
