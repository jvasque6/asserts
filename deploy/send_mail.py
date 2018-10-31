# -*- coding: utf-8 -*-
"""Send notification email."""

import os
import ntpath
from glob import glob
from git import Repo
import mandrill

API_KEY = '***REMOVED***'


def _get_changelog():
    """Get message of last commit."""
    repo = Repo(os.getcwd())
    changelog = repo.git.log('-1', '--pretty=<b>%s</b>\n%b')
    return changelog.replace("\n", "<br />\n")


def _get_version():
    """Get version of last deploy."""
    path_zip = glob('build/dist/*.zip')[0]
    return ntpath.basename(path_zip)[13:-4]


def send_mail(template_name, email_to, context):
    """Send notification email."""
    mandrill_client = mandrill.Mandrill(API_KEY)
    message = {
        'to': [],
        'global_merge_vars': []
    }
    for email in email_to:
        message['to'].append({'email': email})

    for key, value in context.items():
        message['global_merge_vars'].append(
            {'name': key, 'content': value}
        )
    mandrill_client.messages.send_template(template_name, [], message)


send_mail('assertsnewversionr', ["engineering@fluidattacks.com"],
          context={'version': _get_version(),
                   'changelog': _get_changelog()})
