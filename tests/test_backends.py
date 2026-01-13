from saas_sso.auth.backends import UserIdentityBackend


def test_authenticate_missing_params():
    backend = UserIdentityBackend()
    assert backend.authenticate(None) is None
    assert backend.authenticate(None, strategy='invalid') is None
    assert backend.authenticate(None, strategy='google', token=None) is None
