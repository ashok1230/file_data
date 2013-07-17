#-*- coding: utf-8 -*-


from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect
from django.template import RequestContext
from uni_form.helpers import FormHelper, Submit
from django.contrib.auth.decorators import login_required
from emo2oauth.authorize import Authorizer, MissingRedirectURI, AuthorizationException
from .forms import AuthorizeForm
from emo2oauth.models import AccessToken, Code
from settings import PLAYGROUND_CLIENT_ID


@login_required
def missing_redirect_uri(request):
    return render_to_response(
        'play/oauth2/missing_redirect_uri.html', 
        {}, 
        RequestContext(request))


@login_required
def authorize(request):
    AccessToken.objects.filter(user=request.user.id, client=PLAYGROUND_CLIENT_ID).delete()
    Code.objects.filter(user=request.user.id, client=PLAYGROUND_CLIENT_ID).delete()
    authen = False
    three_legged = []
    scopes = request.REQUEST.get('scope')
    list_scope = (scopes.replace(' ', '%20')).split('%20')
    for x in list_scope:
        if x not in three_legged:
            authen = True
            continue
    authorizer = Authorizer()
    try:
        authorizer.validate(request)
    except MissingRedirectURI:
        return HttpResponseRedirect("/oauth/oauth2/missing_redirect_uri")
    except AuthorizationException:
        # The request is malformed or invalid. Automatically 
        # redirects to the provided redirect URL.
        return authorizer.error_redirect()
    if request.method == 'GET':
        if authen == True:
            # Make sure the authorizer has validated before requesting the client
            # or access_ranges as otherwise they will be None.
            template = {
              "client":authorizer.client, 
        	    "access_ranges":authorizer.access_ranges}
            template["form"] = AuthorizeForm()
            helper = FormHelper()
            yes_submit = Submit('connect', 'Allow Access', css_class='authButton')
            helper.add_input(yes_submit)
            no_submit = Submit('connect','No Thanks', css_class='authButton')
            helper.add_input(no_submit)
            helper.form_action = '/oauth/oauth2/authorize?%s' % authorizer.query_string
            helper.form_method = 'POST'
            template["helper"] = helper
            return render_to_response(
        	    'play/oauth2/authorize.html', 
    		    template, 
    		    RequestContext(request))
        else:
            return authorizer.grant_redirect()

    elif request.method == 'POST':
        form = AuthorizeForm(request.POST)
        if form.is_valid():
            if request.POST.get("connect") == 'Allow Access':
                return authorizer.grant_redirect()
            else:
                return authorizer.error_redirect()
    return HttpResponseRedirect("/oauth/")
authorize
-----------------------------------------------------------

def SecretRefresh(request):
    client_id = request.POST.get('client_id')
    try:
        query = Client.objects.get(user=request.user, id=client_id)
        query.secret = sha512(uuid4().hex).hexdigest()[0:CLIENT_SECRET_LENGTH]
        query.save()
        return HttpResponseRedirect(request.META['HTTP_REFERER'])
    except:
        return HttpResponseRedirect(request.META['HTTP_REFERER'])
---------------------------------------------------------------------
notification

from django.http import HttpResponse
from django.contrib.auth.decorators import login_required

import zmq

from zmq_settings import user_publisher_host, user_publisher_port
from django.contrib.auth.models import User
from notification_core.extra import commonReturn

context = zmq.Context()

user_publisher = context.socket(zmq.PUB)
user_publisher.bind(user_publisher_host+':'+user_publisher_port)


def user_notification(request, types=None):
    try:
        service = request.GET.get('service')
        message = request.GET.get('message')
        user= request.GET.get('username')
        user_id = User.objects.get(username__iexact=user).id
        final_message = str(user_id+'_'+service+'_'+message)
        user_publisher.send(final_message)
        status = "Success"
        message = "Notification send successfully to %s. Message was- %s " %(user_id, final_message)
    except:
        status = "Error"
        message = "Notification sending failed"
    return commonReturn(status, message, types)
    

@login_required
def resp(request):
    return HttpResponse(request.user.get_full_name())
-------------------------------------------------------------------
