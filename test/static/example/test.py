#/usr/bin/python
"""Test exploit."""

from fluidasserts.format import string
import requests

otp = '12345'
cookie = 'Cookie: '
string.is_otp_token_insecure(otp)
