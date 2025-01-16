from saas_base.test import SaasTestCase
from saas_sso.models import UserIdentity


class TestUserIdentities(SaasTestCase):
    user_id = SaasTestCase.GUEST_USER_ID

    def test_list_empty_identities(self):
        self.force_login()

        resp = self.client.get('/m/user/identities')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_list_google_identity(self):
        UserIdentity.objects.create(
            user_id=self.user_id,
            strategy='google',
            subject='google-1',
            profile={'name': 'Google', 'email': 'google-1@gmail.com'},
        )
        self.force_login()
        resp = self.client.get('/m/user/identities')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 1)
