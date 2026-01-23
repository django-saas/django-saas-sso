import os
import json
from urllib.parse import urlparse, parse_qs
from saas_base.test import SaasTestCase
from requests_mock import Mocker

ROOT = os.path.dirname(__file__)


class FixturesTestCase(SaasTestCase):
    def resolve_url_params(self, url: str) -> dict[str, str]:
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        location = resp.get('Location')
        params = parse_qs(urlparse(location).query)
        return {k: v[0] for k, v in params.items()}

    @staticmethod
    def load_fixture(name: str):
        filename = os.path.join(ROOT, 'fixtures', name)
        with open(filename) as f:
            if filename.endswith('.json'):
                data = json.load(f)
            else:
                data = f.read()
        return data

    @classmethod
    def mock_requests(cls, *names: str):
        m = Mocker()
        for name in names:
            data = cls.load_fixture(name)
            m.register_uri(**data)
        return m
