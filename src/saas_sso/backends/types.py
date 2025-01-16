import typing as t
from datetime import datetime

OAuth2Token = t.TypedDict("OAuth2Token", {
    "access_token": str,
    "refresh_token": str,
    "expires_in": int,
    "id_token": str,
}, total=False)

OAuth2Options = t.TypedDict("OAuth2Options", {
    "client_id": str,
    "client_secret": str,
    "scope": str,
}, total=False)

Placement = t.Literal['header', 'uri', 'body']


UserInfo = t.TypedDict("UserInfo", {
    "sub": str,
    "name": str,
    "email": str,
    "email_verified": bool,
    "preferred_username": str,
    "family_name": str,
    "given_name": str,
    "middle_name": str,
    "nickname": str,
    "picture": str,
    "website": str,
    "gender": str,
    "birthdate": str,
    "zoneinfo": str,
    "locale": str,
    "updated_at": datetime,
}, total=False)
