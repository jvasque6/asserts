# -*- coding: utf-8 -*-
"""Envia email de notificacion."""

import mandrill

API_KEY = '***REMOVED***'


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


send_mail('assertsnewversionr', ["engineering@fluid.la"],
          context={'Name': "Bob Marley"})
