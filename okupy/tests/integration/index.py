# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.test.client import Client
from okupy.common.testcase import OkupyTestCase

class IndexTests(OkupyTestCase):
    def setUp(self):
        self.client = Client()

    def test_template(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed('index.html')
