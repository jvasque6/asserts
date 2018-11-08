# -*- coding: utf-8 -*-

"""AWS cloud helper."""

# standard imports
# None

# 3rd party imports
import boto3
import botocore

# local imports
# None


class ConnError(botocore.vendored.requests.exceptions.ConnectionError):
    """
    A connection error occurred.

    :py:exc:`ConnectionError` wrapper exception.
    """

    pass


class ClientErr(botocore.exceptions.BotoCoreError):
    """
    A connection error occurred.

    :py:exc:`ClientError` wrapper exception.
    """

    pass


def get_aws_client(service: str, key_id: str, secret: str) -> object:
    """
    Get AWS client object.

    :param service: AWS Service
    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    return boto3.client(service, aws_access_key_id=key_id,
                        aws_secret_access_key=secret,
                        region_name='us-east-1')


def get_credentials_report(key_id: str, secret: str) -> dict:
    """
    Get IAM credentials report.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('iam',
                                key_id=key_id,
                                secret=secret)
        client.generate_credential_report()
        response = client.get_credential_report()
        users = response['Content'].decode().split('\n')[1:]
        return [x.split(',') for x in users]
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def get_account_password_policy(key_id: str, secret: str) -> dict:
    """
    Get IAM account password policy.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('iam',
                                key_id=key_id,
                                secret=secret)
        response = client.get_account_password_policy()
        return response['PasswordPolicy']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def get_account_summary(key_id: str, secret: str) -> dict:
    """
    Get IAM account summary.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('iam',
                                key_id=key_id,
                                secret=secret)
        response = client.get_account_summary()
        return response['SummaryMap']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def list_users(key_id: str, secret: str) -> dict:
    """
    List IAM users.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('iam',
                                key_id=key_id,
                                secret=secret)
        response = client.list_users()
        return response['Users']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def list_attached_user_policies(key_id: str, secret: str, user: str) -> dict:
    """
    List attacked user policies.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    :param user: IAM user
    """
    try:
        client = get_aws_client('iam',
                                key_id=key_id,
                                secret=secret)
        response = client.list_attached_user_policies(UserName=user)
        return response['AttachedPolicies']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def list_trails(key_id: str, secret: str) -> dict:
    """
    List CLOUDTRAIL trails.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('cloudtrail',
                                key_id=key_id,
                                secret=secret)
        response = client.describe_trails()
        return response['trailList']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def list_security_groups(key_id: str, secret: str) -> dict:
    """
    List EC2 security groups.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('ec2',
                                key_id=key_id,
                                secret=secret)
        response = client.describe_security_groups()
        return response['SecurityGroups']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def list_volumes(key_id: str, secret: str) -> dict:
    """
    List EC2 EBS volumes.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('ec2',
                                key_id=key_id,
                                secret=secret)
        response = client.describe_volumes()
        return response['Volumes']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def list_buckets(key_id: str, secret: str) -> dict:
    """
    List S3 buckets.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('s3',
                                key_id=key_id,
                                secret=secret)
        response = client.list_buckets()
        return response['Buckets']
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr


def get_bucket_logging(key_id: str, secret: str, bucket: str) -> dict:
    """
    List S3 bucket logging config.

    :param key_id: AWS Key Id
    :param secret: AWS Key Secret
    """
    try:
        client = get_aws_client('s3',
                                key_id=key_id,
                                secret=secret)
        response = client.get_bucket_logging(Bucket=bucket)
        return response
    except botocore.vendored.requests.exceptions.ConnectionError:
        raise ConnError
    except botocore.exceptions.ClientError:
        raise ClientErr
