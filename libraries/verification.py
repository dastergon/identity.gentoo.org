from django.contrib.sites.models import Site
from django.core.mail import send_mail
from okupy.libraries.encryption import random_string
from okupy.libraries.exception import OkupyException, log_extra_data
import logging

logger = logging.getLogger('okupy')

def sendConfirmationEmail(request, form, model):
    '''
    Create a random URL, add it to the appropriate table along with
    the user data, and send an email to the user to confirm his email address
    '''
    random_url = random_string(30)
    inactive_email = model(email = form.cleaned_data['email'],
                                    user = form.cleaned_data['username'],
                                    url = random_url)
    try:
        inactive_email.save()
    except Exception as error:
        logger.error(error, extra = log_extra_data(request, form))
        raise OkupyException('Could not save to DB')
    send_mail('[%s]: Please confirm your email address' % Site.objects.get_current().name or None,
        'To confirm your email address, please click <a href="/%s">here</a>' % random_url,
        'admin@tampakrap.gr',
        [form.cleaned_data['email']])

def checkConfirmationKey(key, model):
    '''
    Check if the URL matches any of the confirmation keys in the database
    '''
    try:
        result = eval(model).objects.get(url = key)
    except eval(model).DoesNotExist as error:
        raise OkupyException('URL not found')
    return result
