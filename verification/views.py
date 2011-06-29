def sendConfirmationEmail(request, credentials, form):
    '''
    Create a random URL and send an email to the user to confirm his email address
    '''
    random_url = random_string(30)
    inactive_email = InactiveEmail(email = credentials['email'],
                                    user = credentials['username'],
                                    url = random_url)
    try:
        inactive_email.save()
    except Exception as error:
        logger.error(error, extra = log_extra_data(request, form))
        raise OkupyException('Could not save to DB')
    send_mail('[Okupy]: Please confirm your email address',
        'To confirm your email address, please click <a href="/%s">here</a>' % random_url,
        'admin@tampakrap.gr',
        [credentials['email']])
