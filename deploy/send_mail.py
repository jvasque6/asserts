# -*- coding: utf-8 -*-
"""Send notification email."""

import os
from git import Repo
import mandrill

API_KEY = '***REMOVED***'


def get_changelog():
    """Get message of last commit."""
    repo = Repo(os.getcwd())
    changelog = repo.git.log('-1', '--pretty=%s')
    return changelog.rstrip()


def send_mail(template_name, email_to, context):
    """Send notification email."""
    mandrill_client = mandrill.Mandrill(API_KEY)
    message = {
        'to': [],
        'global_merge_vars': []
    }
    for email in email_to:
        message['to'].append({'email': email})

    for key, value in context.iteritems():
        message['global_merge_vars'].append(
            {'name': key, 'content': value}
        )
    mandrill_client.messages.send_template(template_name, [], message)


send_mail('assertsnewversionr', ["engineering@fluidattacks.com"],
          context={'changelog': get_changelog()})
