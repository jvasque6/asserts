# -*- coding: utf-8 -*-
"""Send notification email."""

import os
import git
import glob
import ntpath
import mandrill

PROJECT = os.environ['PROJECT']
PROJECT_URL = os.environ['PROJECT_URL']

MANDRILL_APIKEY = os.environ['MANDRILL_APIKEY']
MANDRILL_NEW_VERSION_EMAIL_TO = \
    os.environ['MANDRILL_NEW_VERSION_EMAIL_TO'].split(',')

CI_COMMIT_SHA = os.environ['CI_COMMIT_SHA']
CI_COMMIT_BEFORE_SHA = os.environ['CI_COMMIT_BEFORE_SHA']


def _get_message() -> str:
    """Get Summary and Author Name of commits."""
    repo = git.Repo(os.getcwd())
    message: str = repo.git.log(
        CI_COMMIT_BEFORE_SHA + '...' + CI_COMMIT_SHA,
        '--pretty=format:<b>%s</b>%n%bCommitted by: %aN%n')
    return message.replace('\n', '<br/>\n')


def _get_version() -> str:
    """Get version of last deploy."""
    path_zip = glob.glob('build/dist/*.zip')[0]
    return ntpath.basename(path_zip)[13:-4]


def send_mail(template_name: str, email_to, context, tags) -> None:
    """Send notification email."""
    mandrill_client = mandrill.Mandrill(MANDRILL_APIKEY)
    message = {
        'to': [
            {'email': email} for email in email_to
        ],
        'global_merge_vars': [
            {'name': key, 'content': value} for key, value in context.items()
        ],
        'tags': tags,
    }
    mandrill_client.messages.send_template(template_name, [], message)


send_mail(
    template_name='new_version',
    email_to=MANDRILL_NEW_VERSION_EMAIL_TO,
    context={
        'project': PROJECT,
        'version': _get_version(),
        'message': _get_message(),
        'project_url': PROJECT_URL,
    },
    tags=[
        'general',
    ])
