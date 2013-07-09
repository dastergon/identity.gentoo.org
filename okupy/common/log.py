# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings


def log_extra_data(additional=None):
    '''
    Extra data needed by the custom formatter
    * If the additional argument is a string or unicode, then its value is
    printed in the log.
    * If the additional argument is the request, then from the request it
    prints the client IP and username if applicable.
    '''
    extra_data = {
        'client_ip': '',
        'id_name': '',
        'instance_name': settings.INSTANCE_NAME,
    }
    if not additional:
        return extra_data
    if type(additional) == str or type(additional) == unicode:
        extra_data['id_name'] = additional
    else:
        request = additional
        if request.META:
            extra_data['client_ip'] = request.META.get('REMOTE_ADDR', 'None')
        try:
            if request.user.is_authenticated():
                '''
                Handle logged in users
                '''
                extra_data['id_name'] = request.user.name
        except AttributeError:
                pass
    return extra_data
