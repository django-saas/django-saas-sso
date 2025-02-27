from urllib.parse import urlparse, parse_qs
from tests.client import FixturesTestCase
from saas_base.models import UserEmail


class TestGitHubLogin(FixturesTestCase):
    user_id = FixturesTestCase.GUEST_USER_ID

    def resolve_state(self, url: str) -> str:
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        location = resp.get('Location')
        params = parse_qs(urlparse(location).query)
        state = params['state'][0]
        return state

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
