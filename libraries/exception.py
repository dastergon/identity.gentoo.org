from django.contrib.sites.models import Site

class OkupyException(Exception):
    '''
    Custon exception class
    '''
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

def log_extra_data(request = None, form = None):
    '''
    Extra data needed by the custom formatter
    All values default to None
    '''
    log_extra_data = {
        'site_name': Site.objects.get_current().name or None,
        'clientip': request.META.get('REMOTE_ADDR','None') if request else None,
        'username': ''
    }
    if form:
        log_extra_data['username'] = form.data.get('username','None')
    else:
        try:
            if request.user.is_authenticated():
                '''
                Handle logged in users
                '''
                log_extra_data['username'] = request.user.name
            else:
                '''
                Handle anonymous users
                '''
                log_extra_data['username'] = 'Anonymous'
        except AttributeError:
            pass
    return log_extra_data
