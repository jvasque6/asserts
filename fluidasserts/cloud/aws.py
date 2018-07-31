# -*- coding: utf-8 -*-

"""AWS cloud checks."""

# standard imports
from datetime import datetime, timedelta
import pytz

# 3rd party imports
from dateutil import parser

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track
from fluidasserts.helper import aws_helper


@track
def iam_has_mfa_disabled(key_id: str, secret: str) -> bool:
    """
    Search users with password enabled and without MFA.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    result = False
    try:
        users = aws_helper.get_credencials_report(key_id, secret)
    except aws_helper.ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    except aws_helper.ClientErr as exc:
        show_unknown('Error retrieving info. Check credentials.',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    for user in users:
        if user[3] == 'true':
            if user[7] == 'false':
                show_open('User has password enabled but without MFA',
                          details=dict(user=user[0]))
                result = True
            else:
                show_close('User has password enabled with MFA',
                           details=dict(user=user[0]))
        else:
            show_close('User has not password enabled',
                       details=dict(user=user[0]))
    return result


@track
def iam_have_old_creds_enabled(key_id: str, secret: str) -> bool:
    """
    Find password not used in the last 90 days.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    result = False
    try:
        users = aws_helper.get_credencials_report(key_id, secret)
    except aws_helper.ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    except aws_helper.ClientErr as exc:
        show_unknown('Error retrieving info. Check credentials.',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    for user in users:
        if user[3] == 'true':
            client = aws_helper.get_aws_client('iam', key_id, secret)
            user_info = client.get_user(UserName=user[0])
            pass_last_used = user_info['User']['PasswordLastUsed']
            if pass_last_used > datetime.now() + timedelta(days=90):
                show_open('User has not used the password in more than 90 \
days and it\'s still active',
                          details=dict(user=user[0],
                                       password_last_used=pass_last_used))
                result = True
            else:
                show_close('User has used the password in the last 90 days',
                           details=dict(user=user[0],
                                        password_last_used=pass_last_used))
    return result


@track
def iam_have_old_access_keys(key_id: str, secret: str) -> bool:
    """
    Find access keys not rotated in the last 90 days.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    result = False
    try:
        users = aws_helper.get_credencials_report(key_id, secret)
    except aws_helper.ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    except aws_helper.ClientErr as exc:
        show_unknown('Error retrieving info. Check credentials.',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    for user in users:
        if user[8] == 'true':
            ak_last_change = parser.parse(user[9]).replace(tzinfo=pytz.UTC)
            now_plus_90 = datetime.now() - timedelta(days=90)
            if ak_last_change < now_plus_90.replace(tzinfo=pytz.UTC):
                show_open('User\'s access key has not been rotated in the \
last 90 days', details=dict(user=user[0],
                            last_rotated=ak_last_change,
                            expected_rotation_time=now_plus_90))
                result = True
            else:
                show_close('User\'s access key has been rotated in the last \
90 days', details=dict(user=user[0],
                       last_rotated=ak_last_change,
                       expected_rotation_time=now_plus_90))
        else:
            show_close('User has not access keys enabled',
                       details=dict(user=user[0]))
    return result


@track
def iam_not_requires_uppercase(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires uppercase letters.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    result = False
    try:
        policy = aws_helper.get_account_password_policy(key_id, secret)
    except aws_helper.ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    except aws_helper.ClientErr as exc:
        show_unknown('Error retrieving info. Check credentials.',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    if policy['RequireUppercaseCharacters']:
        show_close('Password policy requires uppercase letters',
                   details=dict(policy=policy))
        result = False
    else:
        show_open('Password policy does not require uppercase letters',
                  details=dict(policy=policy))
        result = True
    return result
