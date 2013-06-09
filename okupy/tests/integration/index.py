# -*- coding: utf-8 -*-

from django.test.client import Client
from okupy.common.testcase import OkupyTestCase

class IndexTests(OkupyTestCase):
    def setUp(self):
        self.client = Client()

    def test_template(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed('index.html')
