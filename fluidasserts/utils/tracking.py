# -*- coding: utf-8 -*-

"""Fluid Asserts tracking module."""

# standard imports
import os
import hashlib
import sys
import platform

# 3rd party imports
from mixpanel import Mixpanel, MixpanelException
import requests


def get_os_fingerprint():
    """Get fingerprint of running OS."""
    sha256 = hashlib.sha256()
    data = sys.platform + sys.version + platform.node()
    sha256.update(data.encode('utf-8'))
    return sha256.hexdigest()


def get_public_ip():
    """Get public IP of system."""
    my_ip = 'Private IP'
    try:
        my_ip = requests.get('https://api.ipify.org').text
    except requests.exceptions.ConnectionError:
        pass
    return my_ip


def mp_track(func_to_track):
    """Track a function."""
    if os.environ.get('FA_NOTRACK') != 'true':
        project_token = '4ddf91a8a2c9f309f6a967d3462a496c'
        mix_pan = Mixpanel(project_token)
        try:
            mix_pan.people_set(get_os_fingerprint(), {'$ip': get_public_ip()})
            mix_pan.track(get_os_fingerprint(), func_to_track)
        except MixpanelException:  # pragma: no cover
            pass
