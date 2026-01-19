import time
from joserfc import jwt
from joserfc.jwk import ECKey
from urllib.parse import urlparse, parse_qs

from requests_mock.mocker import Mocker
from django.contrib.auth import get_user_model
from django.conf import settings
from django.test import override_settings

from tests.client import FixturesTestCase
from saas_base.models import UserEmail
from saas_sso.models import UserIdentity

UserModel = get_user_model()
DEFAULT_SAAS_SSO = settings.SAAS_SSO.copy()


class TestOAuthLogin(FixturesTestCase):
    user_id = FixturesTestCase.GUEST_USER_ID

    def resolve_state(self, url: str) -> str:
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        location = resp.get('Location')
        params = parse_qs(urlparse(location).query)
        state = params['state'][0]
        return state

    def generate_apple_id_token(self):
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
        return jwt.encode(header, claims, key)

    def mock_apple_id_token(self, m: Mocker):
        id_token = self.generate_apple_id_token()
        m.register_uri(
            'POST',
            'https://appleid.apple.com/auth/token',
            json={
                'access_token': 'apple-access-token',
                'expires_in': 3600,
                'id_token': id_token,
            },
        )

    def mock_google_id_token(self, m: Mocker):
        key = ECKey.import_key(self.load_fixture('apple_private_key.p8'))
        now = int(time.time())
        claims = {
            'iss': 'https://accounts.google.com',
            'aud': 'google_client_id',
            'exp': now + 3600,
            'iat': now,
            'sub': 'google-user-sub',
            'email': 'google-id-token@example.com',
            'email_verified': True,
        }
        header = {'kid': 'test-key-id', 'alg': 'ES256'}
        id_token = jwt.encode(header, claims, key)
        m.register_uri(
            'POST',
            'https://oauth2.googleapis.com/token',
            json={
                'access_token': 'google-access-token',
                'expires_in': 3600,
                'id_token': id_token,
            },
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
            return resp

    def test_google_not_create_user(self):
        state = self.resolve_state('/m/login/google/')

        with self.mock_requests(
            'google_token.json',
            'google_user.json',
        ):
            resp = self.client.get(f'/m/auth/google/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)
            count = UserIdentity.objects.filter(strategy='google').count()
            self.assertEqual(count, 0)

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_google_id_token_create_user(self):
        state = self.resolve_state('/m/login/google/')

        with Mocker() as m:
            m.register_uri(
                'GET', 'https://www.googleapis.com/oauth2/v3/certs', json=self.load_fixture('apple_jwks.json')['json']
            )
            self.mock_google_id_token(m)
            resp = self.client.get(f'/m/auth/google/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)

            # Verify identity created
            identity = UserIdentity.objects.get(strategy='google', subject='google-user-sub')
            self.assertEqual(identity.profile['email'], 'google-id-token@example.com')

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_google_flow_with_preferred_username(self):
        state = self.resolve_state('/m/login/google/')

        with self.mock_requests('google_token.json', 'google_user_pref.json'):
            resp = self.client.get(f'/m/auth/google/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)
            identity = UserIdentity.objects.get(strategy='google', subject='google-pref')
            self.assertEqual(identity.user.username, 'google_user')

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_google_flow_email_not_verified(self):
        state = self.resolve_state('/m/login/google/')

        with self.mock_requests('google_token.json', 'google_user_unverified.json'):
            resp = self.client.get(f'/m/auth/google/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)

            # Verify user created but email NOT in UserEmail table
            identity = UserIdentity.objects.get(strategy='google', subject='google-unverified')
            self.assertFalse(UserEmail.objects.filter(user=identity.user, email='unverified@example.com').exists())

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
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

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
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

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_apple_flow_code_exchange(self):
        state = self.resolve_state('/m/login/apple/')
        id_token = self.generate_apple_id_token()

        with self.mock_requests('apple_jwks.json') as m:
            m.register_uri(
                'POST',
                'https://appleid.apple.com/auth/token',
                json={
                    'access_token': 'apple-access-token',
                    'expires_in': 3600,
                    'id_token': id_token,
                },
            )
            # NO id_token in POST data
            resp = self.client.post(
                '/m/auth/apple/',
                data={'state': state, 'code': '123'},
                format='multipart',
            )
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(UserIdentity.objects.filter(strategy='apple', subject='apple-user-sub').exists())

    def test_fetch_no_userinfo(self):
        resp = self.client.get('/m/sso/userinfo/')
        self.assertEqual(resp.status_code, 404)

    def test_github_not_auto_create_user(self):
        self.assertFalse(UserEmail.objects.filter(email='octocat@github.com').exists())
        self.run_github_flow()
        self.assertFalse(UserEmail.objects.filter(email='octocat@github.com').exists())

        # we can fetch userinfo from session
        resp = self.client.get('/m/sso/userinfo/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['preferred_username'], 'octocat')

        # then we can create user
        resp = self.client.post('/m/sso/create-user/', data={'username': 'octocat'})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(UserEmail.objects.filter(email='octocat@github.com').exists())

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'TRUST_EMAIL_VERIFIED': True})
    def test_github_auto_connect_user(self):
        self.assertFalse(UserIdentity.objects.filter(strategy='github').exists())
        user = UserModel.objects.create_user('username', 'demo@example.com')
        UserEmail.objects.create(user=user, email='octocat@github.com')
        self.run_github_flow()
        self.assertTrue(UserIdentity.objects.filter(strategy='github').exists())

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'TRUST_EMAIL_VERIFIED': True})
    def test_github_no_related_user(self):
        self.assertFalse(UserIdentity.objects.filter(strategy='github').exists())
        self.run_github_flow()
        self.assertFalse(UserIdentity.objects.filter(strategy='github').exists())

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_github_auto_create_user(self):
        self.assertFalse(UserEmail.objects.filter(email='octocat@github.com').exists())
        self.run_github_flow()
        self.assertTrue(UserEmail.objects.filter(email='octocat@github.com').exists())
        # the next flow will auto login
        self.run_github_flow()

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_duplicate_username_fallback(self):
        # Create user with username 'collision'
        UserModel.objects.create_user(username='collision', email='original@example.com')

        state = self.resolve_state('/m/login/github/')

        # GitHub user has login 'collision' but different email
        with self.mock_requests('github_token.json', 'github_user_collision.json', 'github_user_collision_emails.json'):
            resp = self.client.get(f'/m/auth/github/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)

            # Verify new user created with different username (UUID)
            identity = UserIdentity.objects.get(strategy='github', subject='999')
            self.assertNotEqual(identity.user.username, 'collision')
            self.assertEqual(identity.user.email, 'new@example.com')

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_github_name_parsing_single(self):
        state = self.resolve_state('/m/login/github/')

        with self.mock_requests('github_token.json', 'github_user_single.json', 'github_user_single_emails.json'):
            resp = self.client.get(f'/m/auth/github/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)

            identity = UserIdentity.objects.get(strategy='github', subject='888')
            self.assertEqual(identity.profile['given_name'], 'SingleName')
            self.assertIsNone(identity.profile['family_name'])

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_github_no_primary_email(self):
        state = self.resolve_state('/m/login/github/')

        with self.mock_requests('github_token.json', 'github_user_noprimary.json', 'github_user_noprimary_emails.json'):
            resp = self.client.get(f'/m/auth/github/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)

            identity = UserIdentity.objects.get(strategy='github', subject='777')
            # Should pick first email
            self.assertEqual(identity.profile['email'], 'secondary@example.com')

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True})
    def test_login_view_next_url(self):
        resp = self.client.get('/m/login/github/?next=/dashboard')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(self.client.session.get('next_url'), '/dashboard')
        resp = self.run_github_flow()
        self.assertEqual(resp.headers['Location'], '/dashboard')

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTO_CREATE_USER': True, 'AUTHORIZED_REDIRECT_URL': '/test'})
    def test_authorized_redirect_url_settings(self):
        self.client.get('/m/login/github/')
        resp = self.run_github_flow()
        self.assertEqual(resp.headers['Location'], '/test')

    @override_settings(SAAS_SSO={**DEFAULT_SAAS_SSO, 'AUTHORIZED_URL': 'http://test/{strategy}'})
    def test_authorization_redirect_url_settings(self):
        resp = self.client.get('/m/login/github/')
        self.assertEqual(resp.status_code, 302)
        location = resp.get('Location')
        params = parse_qs(urlparse(location).query)
        redirect_uri = params['redirect_uri'][0]
        self.assertEqual(redirect_uri, 'http://test/github')
