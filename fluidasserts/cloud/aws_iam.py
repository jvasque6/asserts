# -*- coding: utf-8 -*-

"""
AWS cloud checks (IAM).

The checks are based on CIS AWS Foundations Benchmark.
"""

# standard imports
from datetime import datetime, timedelta
import pytz

# 3rd party imports
from dateutil import parser

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level
from fluidasserts.helper import aws_helper


@level('high')
@track
def has_mfa_disabled(key_id: str, secret: str) -> bool:
    """
    Search users with password enabled and without MFA.

    CIS 1.2: Ensure multi-factor authentication (MFA) is enabled for all IAM
    users that have a console password (Scored)

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
            show_close('User does not have password enabled',
                       details=dict(user=user[0]))
    return result


@level('medium')
@track
def have_old_creds_enabled(key_id: str, secret: str) -> bool:
    """
    Find password not used in the last 90 days.

    CIS 1.3: Ensure credentials unused for 90 days or greater are
    disabled (Scored)

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
                show_open('User does not have used the password in more than \
                    90 days and it\'s still active',
                          details=dict(user=user[0],
                                       password_last_used=pass_last_used))
                result = True
            else:
                show_close('User has used the password in the last 90 days',
                           details=dict(user=user[0],
                                        password_last_used=pass_last_used))
    return result


@level('medium')
@track
def have_old_access_keys(key_id: str, secret: str) -> bool:
    """
    Find access keys not rotated in the last 90 days.

    CIS 1.4: Ensure access keys are rotated every 90 days or less (Scored)

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
                show_open('User\'s access key does not have been rotated in \
                    the last 90 days',
                          details=dict(user=user[0],
                                       last_rotated=ak_last_change,
                                       expected_rotation_time=now_plus_90))
                result = True
            else:
                show_close('User\'s access key has been rotated in the last \
90 days', details=dict(user=user[0],
                       last_rotated=ak_last_change,
                       expected_rotation_time=now_plus_90))
        else:
            show_close('User does not have access keys enabled',
                       details=dict(user=user[0]))
    return result


@level('high')
@track
def root_has_access_keys(key_id: str, secret: str) -> bool:
    """
    Check if root account has access keys.

    CIS 1.12: Ensure no root account access key exists (Scored)

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
        show_close('Root user does not have access keys',
                   details=dict(user=root_user))
        result = False
    return result


@level('high')
@track
def not_requires_uppercase(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires uppercase letters.

    CIS 1.5: Ensure IAM password policy requires at least one uppercase
    letter (Scored)

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


@level('high')
@track
def not_requires_lowercase(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires lowercase letters.

    CIS 1.6: Ensure IAM password policy require at least one lowercase
    letter (Scored)

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


@level('high')
@track
def not_requires_symbols(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires symbols.

    CIS 1.7: Ensure IAM password policy require at least one symbol (Scored)

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


@level('high')
@track
def not_requires_numbers(key_id: str, secret: str) -> bool:
    """
    Check if password policy requires numbers.

    CIS 1.8: Ensure IAM password policy require at least one number (Scored)

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


@level('high')
@track
def min_password_len_unsafe(key_id: str, secret: str, min_len=14) -> bool:
    """
    Check if password policy requires passwords greater than 14 chars.

    CIS 1.9: Ensure IAM password policy requires minimum length of 14 or
    greater (Scored)

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
    if policy['MinimumPasswordLength'] >= min_len:
        show_close('Password policy requires long passwords',
                   details=dict(min_length=min_len, policy=policy))
        result = False
    else:
        show_open('Password policy does not require long passwords',
                  details=dict(min_length=min_len, policy=policy))
        result = True
    return result


@level('medium')
@track
def password_reuse_unsafe(key_id: str, secret: str, min_reuse=24) -> bool:
    """
    Check if password policy avoids reuse of the last 24 passwords.

    CIS 1.10: Ensure IAM password policy prevents password reuse: 24 or
    greater (Scored)

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


@level('medium')
@track
def password_expiration_unsafe(key_id: str, secret: str, max_days=90) -> bool:
    """
    Check if password policy expires the passwords within 90 days or less.

    CIS 1.11: Ensure IAM password policy expires passwords within 90 days
    or less (Scored)

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
        if policy['MaxPasswordAge'] <= max_days:
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


@level('high')
@track
def root_without_mfa(key_id: str, secret: str) -> bool:
    """
    Check if root account does not have MFA.

    CIS 1.13: Ensure MFA is enabled for the root account (Scored)

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


@level('low')
@track
def policies_attached_to_users(key_id: str, secret: str) -> bool:
    """
    Check if there are policies attached to users.

    CIS 1.16: Ensure IAM policies are attached only to groups or
    roles (Scored)

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    result = False
    try:
        users = aws_helper.list_users(key_id, secret)
    except aws_helper.ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    except aws_helper.ClientErr as exc:
        show_unknown('Error retrieving info. Check credentials.',
                     details=dict(error=str(exc).replace(':', '')))
        return False
    for user in users:
        user_pol = aws_helper.list_attached_user_policies(key_id,
                                                          secret,
                                                          user['UserName'])
        if user_pol:
            show_open('User has policies directly attached',
                      details=(dict(user=user['UserName'],
                                    user_policy=user_pol)))
            result = True
        else:
            show_close('User does not have policies attached',
                       details=(dict(user=user['UserName'])))
    return result
