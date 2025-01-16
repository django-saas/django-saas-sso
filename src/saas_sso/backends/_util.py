import typing as t
from urllib import parse as urlparse
from joserfc.util import to_bytes, to_str


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
