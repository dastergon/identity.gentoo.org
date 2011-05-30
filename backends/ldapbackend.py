from django.conf import settings
from django.contrib.auth.models import User
import ldap

class LDAPBackend(object):
	def bind(self, username, password, base_attr, base_dn):
		l = ldap.initialize('ldap://localhost')
		try:
			if settings.LDAP_TLS:
				l.set_option(ldap.OPT_X_TLS_DEMAND, True)
				l.start_tls_s()
		except:
			pass
		bind_dn = '%s=%s,%s' % (base_attr, username, base_dn)
		try:
			l.simple_bind_s(bind_dn, password)
			return l
		except ldap.INVALID_CREDENTIALS:
			return None

	def authenticate(self, username = None, password = None):
		if not password:
			return None
		return self.get_or_create_user(username, password)

	def get_or_create_user(self, username, password):
		try:
			user = User.objects.get(username = username)
		except User.DoesNotExist:
			try:
				if settings.LDAP_ANON_USER_DN:
					ldap_anon_user_username = settings.LDAP_ANON_USER_DN.split('=')[1].split(',')[0]
					ldap_anon_user_attr = settings.LDAP_ANON_USER_DN.split('=')[0]
					ldap_anon_user_base_dn = ','.join(settings.LDAP_ANON_USER_DN.split(',')[1:])
					l = self.bind(ldap_anon_user_username,
									settings.LDAP_ANON_USER_PW,
									ldap_anon_user_attr,
									ldap_anon_user_base_dn)

					for ldap_base_dn in settings.LDAP_BASE_DN:
						results = l.search_s(ldap_base_dn,
											ldap.SCOPE_SUBTREE,
											'(%s=%s)' % (settings.LDAP_BASE_ATTR, username),
											['*'])
						try:
							if results:
								break
						except AttributeError:
							pass
					if not results:
						return None

					l.unbind_s()

				for ldap_base_dn in settings.LDAP_BASE_DN:
					l_user = self.bind(username, password,
									settings.LDAP_BASE_ATTR,
									ldap_base_dn)
					try:
						if l_user:
							break
					except AttributeError:
						pass
				if not l_user:
					return None
				l_user.unbind()
			except ImportError:
				pass
			except ldap.INVALID_CREDENTIALS:
				return None

			user = User()
			for field, attr in settings.LDAP_USER_ATTR_MAP.iteritems():
				setattr(user, field, results[0][1][attr][0])
			user.username = username
			user.set_unusable_password()
			try:
				user.save()
			except Exception as error:
				print error
				
#			if settings.LDAP_PROFILE_ATTR_MAP:
#				user_profile = UserProfile()
#				for field, attr in settings.LDAP_PROFILE_ATTR_MAP.iteritems():
#					setattr(user_profile, field, results[attr][0])
#				user_profile.save()
			return user
