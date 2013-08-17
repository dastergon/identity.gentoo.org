# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from ...accounts.openid_store import DjangoDBOpenIDStore
from ...common.test_helpers import OkupyTestCase

import time


class OpenIDStoreTests(OkupyTestCase):
	def setUp(self):
		self.store = DjangoDBOpenIDStore()

	def test_nonce_integrity(self):
		nonce = ('http://example.com', time.time(), 'pepper')
		# first one should succeed, the second one should fail because
		# of reused nonce
		self.assertTrue(self.store.useNonce(*nonce))
		self.assertFalse(self.store.useNonce(*nonce))
