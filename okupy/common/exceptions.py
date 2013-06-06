# -*- coding: utf-8 -*-

class OkupyError(Exception):
    '''
    Custon exception class for general errors
    '''
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return unicode(self.value).encode('utf-8')

class LoginError(Exception):
    '''
    Custom exception class for login failures
    '''
    def __init__(self):
        self.value = u'Login failed'
    def __str__(self):
        return unicode(self.value).encode('utf-8')

class SignupError(Exception):
    '''
    Custom exception class for signup failures
    '''
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return unicode(self.value).encode('utf-8')
