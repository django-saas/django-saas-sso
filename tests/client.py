import os
import json
from saas_base.test import SaasTestCase
from requests_mock import Mocker

ROOT = os.path.dirname(__file__)


class FixturesTestCase(SaasTestCase):
    @staticmethod
    def load_fixture(name: str):
        filename = os.path.join(ROOT, 'fixtures', name)
        with open(filename) as f:
            data = json.load(f)
        return data

    @classmethod
    def mock_requests(cls, *names: str):
        m = Mocker()
        for name in names:
            data = cls.load_fixture(name)
            m.register_uri(**data)
        return m
