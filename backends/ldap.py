import ldap

class LDAPBackend(object):
	def bind(self, username, password):
		l = ldap.initialize(settings.LDAP_URI)
		if settings.LDAP_TLS:
			l.set_option(ldap.OPT_X_TLS_DEMAND, True)
			l.start_tls_s()
		bind_dn = '%s=%s%s' % (settings.LDAP_BASE_ATTR, username, settings.LDAP_BASE_DN)
		l.simple_bind_s(bind_dn, password)
		return l

	def authenticate(self, username = None, password = None):
		if not password:
			return None
		l = self.bind(username, password)
		l.unbind_s()
		return self.get_or_create_user(username, password)

	def get_or_create_user(self, username, password):
		try:
			user = User.objects.get(username = username)
		except User.DoesNotExist:
			try:
				if settings.LDAP_ANON_USERNAME:
					l = self.bind(settings.LDAP_ANON_USERNAME,
									settings.LDAP_ANON_PW)
				else:
					l = self.bind(username, password)

				results = l.search_s(settings.LDAP_BASE_DN,
									ldap.SCOPE_SUBTREE,
									uid)
				if not results:
					print 'no results'
					return None

				user = User()
				for field, attr in settings.LDAP_USER_ATTR_MAP.iteritems():
					setattr(user, field, results[attr][0])
				user.username = username
				user.set_unusable_password()
				user.save()
				
				if settings.LDAP_PROFILE_ATTR_MAP:
					user_profile = UserProfile()
					for field, attr in settings.LDAP_PROFILE_ATTR_MAP.iteritems():
						setattr(user_profile, field, results[attr][0])
					user_profile.save()

			except ImportError:
				pass
			except ldap.INVALID_CREDENTIALS as e:
				print e
				return None
			except ldap.LDAPError, e:
				print e
				return None
