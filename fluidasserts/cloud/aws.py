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
        users = aws_helper.get_credentials_report(key_id, secret)
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
        users = aws_helper.get_credentials_report(key_id, secret)
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
        users = aws_helper.get_credentials_report(key_id, secret)
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
def iam_root_has_access_keys(key_id: str, secret: str) -> bool:
    """
    Check if root account has access keys.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    result = False
    try:
        users = aws_helper.get_credentials_report(key_id, secret)
    except aws_helper.ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    except aws_helper.ClientErr as exc:
        show_unknown('Error retrieving info. Check credentials.',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    root_user = users[0]
    if root_user[8] == 'true' or root_user[13] == 'true':
        show_open('Root user has access keys', details=dict(user=root_user))
        result = True
    else:
        show_close('Root user has not access keys',
                   details=dict(user=root_user))
        result = False
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


@track
def iam_not_requires_lowercase(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires lowercase letters.

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
    if policy['RequireLowercaseCharacters']:
        show_close('Password policy requires lowercase letters',
                   details=dict(policy=policy))
        result = False
    else:
        show_open('Password policy does not require lowercase letters',
                  details=dict(policy=policy))
        result = True
    return result


@track
def iam_not_requires_symbols(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires symbols.

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
    if policy['RequireSymbols']:
        show_close('Password policy requires symbols',
                   details=dict(policy=policy))
        result = False
    else:
        show_open('Password policy does not require symbols',
                  details=dict(policy=policy))
        result = True
    return result


@track
def iam_not_requires_numbers(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires numbers.

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
    if policy['RequireNumbers']:
        show_close('Password policy requires numbers',
                   details=dict(policy=policy))
        result = False
    else:
        show_open('Password policy does not require numbers',
                  details=dict(policy=policy))
        result = True
    return result


@track
def iam_min_password_len_unsafe(key_id: str, secret: str, min_len=14) -> bool:
    """
    Check if password policy requires passwords greater than 14 chars.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    :param min_len: Mininum length required. Default 14
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
    if policy['MinimumPasswordLength'] > min_len:
        show_close('Password policy requires long passwords',
                   details=dict(min_length=min_len, policy=policy))
        result = False
    else:
        show_open('Password policy does not require long passwords',
                  details=dict(min_length=min_len, policy=policy))
        result = True
    return result


@track
def iam_password_reuse_unsafe(key_id: str, secret: str, min_reuse=24) -> bool:
    """
    Check if password policy avoids reuse of the last 24 passwords.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    :param min_len: Mininum reuse required. Default 24
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
    if 'PasswordReusePrevention' in policy:
        if policy['PasswordReusePrevention'] >= min_reuse:
            show_close('Password policy avoid reusing passwords',
                       details=dict(min_reuse=min_reuse, policy=policy))
            result = False
        else:
            show_open('Password policy allows reusing passwords',
                      details=dict(min_reuse=min_reuse, policy=policy))
            result = True
    else:
        show_open('Password policy not contains reuse clause',
                  details=dict(policy=policy))
        result = True
    return result


@track
def iam_password_expiration_unsafe(key_id: str, secret: str,
                                   max_days=90) -> bool:
    """
    Check if password policy expires the passwords within 90 days or less.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    :param max_days: Max expiration days. Default 90
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
    if 'MaxPasswordAge' in policy:
        if policy['MaxPasswordAge'] >= max_days:
            show_close('Password policy expiration policy is safe',
                       details=dict(max_days=max_days, policy=policy))
            result = False
        else:
            show_open('Password policy expiration policy is not safe',
                      details=dict(max_days=max_days, policy=policy))
            result = True
    else:
        show_open('Password policy not contains expiration clause',
                  details=dict(policy=policy))
        result = True
    return result


@track
def iam_root_without_mfa(key_id: str, secret: str) -> bool:
    """
    Check if root account has MFA.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    result = False
    try:
        summary = aws_helper.get_account_summary(key_id, secret)
    except aws_helper.ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    except aws_helper.ClientErr as exc:
        show_unknown('Error retrieving info. Check credentials.',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    if summary['AccountMFAEnabled'] == 1:
        show_close('Root password has MFA enabled',
                   details=dict(account_summary=summary))
        result = False
    else:
        show_open('Root password has MFA disabled',
                  details=dict(account_summary=summary))
        result = True
    return result
