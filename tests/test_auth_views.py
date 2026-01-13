import time
from joserfc import jwt
from joserfc.jwk import ECKey
from urllib.parse import urlparse, parse_qs

from requests_mock.mocker import Mocker

from tests.client import FixturesTestCase
from saas_base.models import UserEmail
from saas_sso.models import UserIdentity


class TestOAuthLogin(FixturesTestCase):
    user_id = FixturesTestCase.GUEST_USER_ID

    def resolve_state(self, url: str) -> str:
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        location = resp.get('Location')
        params = parse_qs(urlparse(location).query)
        state = params['state'][0]
        return state

    def mock_apple_id_token(self, m: Mocker):
        key = ECKey.import_key(self.load_fixture('apple_private_key.p8'))
        now = int(time.time())
        claims = {
            'iss': 'https://appleid.apple.com',
            'aud': 'apple_client_id',
            'exp': now + 3600,
            'iat': now,
            'sub': 'apple-user-sub',
            'email': 'apple@example.com',
            'email_verified': True,
        }
        header = {'kid': 'test-key-id', 'alg': 'ES256'}
        id_token = jwt.encode(header, claims, key)
        m.register_uri(
            'POST',
            'https://appleid.apple.com/auth/token',
            json={
                'access_token': 'apple-access-token',
                'expires_in': 3600,
                'id_token': id_token,
            }
        )

    def test_invalid_strategy(self):
        resp = self.client.get('/m/login/invalid/')
        self.assertEqual(resp.status_code, 404)
        resp = self.client.get('/m/auth/invalid/')
        self.assertEqual(resp.status_code, 404)

    def test_mismatch_state(self):
        resp = self.client.get('/m/login/github/')
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get('/m/auth/github/?state=abc&code=123')
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b'<h1>400</h1>', resp.content)

    def run_github_flow(self):
        state = self.resolve_state('/m/login/github/')

        with self.mock_requests(
            'github_token.json',
            'github_user.json',
            'github_user_primary_emails.json',
        ):
            resp = self.client.get(f'/m/auth/github/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)

    def test_github_login(self):
        self.assertEqual(UserEmail.objects.filter(email='octocat@github.com').count(), 0)
        self.run_github_flow()
        self.assertEqual(UserEmail.objects.filter(email='octocat@github.com').count(), 1)
        # the next flow will auto login
        self.run_github_flow()

    def test_google_flow(self):
        state = self.resolve_state('/m/login/google/')

        with self.mock_requests(
            'google_token.json',
            'google_user.json',
        ):
            resp = self.client.get(f'/m/auth/google/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)

    def test_apple_flow(self):
        state = self.resolve_state('/m/login/apple/')

        # Test Apple's POST callback (form_post)
        with self.mock_requests('apple_jwks.json') as m:
            self.mock_apple_id_token(m)
            resp = self.client.post(
                '/m/auth/apple/',
                data={'state': state, 'code': '123'},
                format='multipart',
            )
            self.assertEqual(resp.status_code, 302)

            # Verify identity creation
            self.assertTrue(UserIdentity.objects.filter(strategy='apple', subject='apple-user-sub').exists())
            # Verify email creation
            self.assertTrue(UserEmail.objects.filter(email='apple@example.com').exists())

    def test_apple_flow_with_user_name(self):
        state = self.resolve_state('/m/login/apple/')
        user_json = '{"name": {"firstName": "Apple", "lastName": "User"}}'

        with self.mock_requests('apple_jwks.json') as m:
            self.mock_apple_id_token(m)
            resp = self.client.post(
                '/m/auth/apple/',
                data={'state': state, 'code': '123', 'user': user_json},
                format='multipart',
            )
            self.assertEqual(resp.status_code, 302)

            # Verify identity profile has name
            identity = UserIdentity.objects.get(strategy='apple', subject='apple-user-sub')
            self.assertEqual(identity.profile['given_name'], 'Apple')
            self.assertEqual(identity.profile['family_name'], 'User')
