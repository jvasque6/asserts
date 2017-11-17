# -*- coding: utf-8 -*-

"""Modulo para verificaciones de Captcha."""


# standard imports
import logging
try:
    import Image
except ImportError:
    from PIL import Image

# 3rd party imports
import requests
import pytesseract

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import http_helper
from fluidasserts.utils.decorators import track

logger = logging.getLogger('FLUIDAsserts')


def is_insecure_in_image(image, expected_text):
    result = pytesseract.image_to_string(Image.open(image))
    if result == expected_text:
        logger.info('%s: Captcha is insecure, \
Details: Expected=%s, Reversed=%s', show_open(), expected_text, result)
        return True
    else:
        logger.info('%s: Captcha is secure, \
Details: Expected=%s, Reversed=%s', show_close(), expected_text, result)
        return False


def is_insecure_in_url(image_url, expected_text, *args, **kwargs):
    session = http_helper.HTTPSession(image_url, stream=True, *args, **kwargs)
    image = session.response.raw
    result = pytesseract.image_to_string(Image.open(image))
    if result == expected_text:
        logger.info('%s: Captcha is insecure, \
Details: Expected=%s, Reversed=%s', show_open(), expected_text, result)
        return True
    else:
        logger.info('%s: Captcha is secure, \
Details: Expected=%s, Reversed=%s', show_close(), expected_text, result)
        return False
