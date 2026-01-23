from tests.client import FixturesTestCase
from saas_sso.models import UserIdentity


class TestConnectViews(FixturesTestCase):
    user_id = FixturesTestCase.GUEST_USER_ID

    def setUp(self):
        super().setUp()
        self.force_login()

    def test_connect_github(self):
        params = self.resolve_url_params('/m/connect/link/github/')

        with self.mock_requests(
            'github_token.json',
            'github_user.json',
            'github_user_primary_emails.json',
        ):
            state = params['state']
            resp = self.client.get(f'/m/connect/auth/github/?state={state}&code=123')
            self.assertEqual(resp.status_code, 302)
            # Should redirect to default redirect url (login redirect url or next)
            # In test setup, LOGIN_REDIRECT_URL might default to /accounts/profile/

            # Verify identity created
            self.assertTrue(UserIdentity.objects.filter(user_id=self.user_id, strategy='github', subject='1').exists())

    def test_connect_google_duplicate(self):
        # Create an existing identity for another user
        UserIdentity.objects.create(
            user_id=self.STAFF_USER_ID,
            strategy='google',
            subject='example@gmail.com',
            profile={},
        )

        params = self.resolve_url_params('/m/connect/link/google/')

        with self.mock_requests(
            'google_token.json',
            'google_user.json',
        ):
            state = params['state']
            resp = self.client.get(f'/m/connect/auth/google/?state={state}&code=123')
            self.assertEqual(resp.status_code, 400)
            self.assertIn(b'already connected to another user', resp.content)
