from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from django.template import RequestContext

@login_required
def account(request, username):
    return render_to_response('account/account.html', {}, context_instance = RequestContext(request))

@login_required
def account_edit(request, username):
    return render_to_response('account/edit.html', {}, context_instance = RequestContext(request))
