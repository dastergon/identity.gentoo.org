from django.contrib.sites.models import Site

class OkupyException(Exception):
    '''
    Custon exception class
    '''
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
