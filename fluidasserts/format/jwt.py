# -*- coding: utf-8 -*-

"""This module allows to check ``JWT`` vulnerabilities."""


# standard imports

# 3rd party imports
from jwt import decode
from jwt.exceptions import InvalidTokenError

# local imports
from fluidasserts import show_open
from fluidasserts import show_close
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level, notify


@notify
@level('low')
@track
def has_insecure_expiration_time(
        jwt_token: str, max_expiration_time: int = 600) -> bool:
    """
    Check if the given JWT has an insecure expiration time.

    :param jwt_token: JWT to test.
    :param max_expiration_time: According to the bussiness rule, (in seconds).
    """
    try:
        claimset = decode(jwt_token, verify=False)
    except InvalidTokenError:
        show_unknown('Unable to decode token.',
                     details=dict(jwt_token=jwt_token))
        return False
    iat = claimset.get('iat')
    exp = claimset.get('exp')
    if not iat or not exp:
        show_open('Token does not include an `iat` or `exp` claims',
                  details=dict(claims_set=claimset))
        return True
    expiration_time = (exp - iat)
    if expiration_time > max_expiration_time:
        show_open('Token has an insecure expiration time',
                  details=dict(claims_set=claimset,
                               expiration_time=expiration_time,
                               max_expiration_time=max_expiration_time))

    else:
        show_close('Token has a secure expiration time',
                   details=dict(claims_set=claimset,
                                expiration_time=expiration_time,
                                max_expiration_time=max_expiration_time))
    return expiration_time > max_expiration_time
