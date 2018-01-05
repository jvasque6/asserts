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
from fluidasserts.helper import http_helper
from fluidasserts.utils.decorators import track

LOGGER = logging.getLogger('FLUIDAsserts')


@track
def is_insecure_in_image(image, expected_text):
    """Verifica si la imagen es un captcha inseguro."""
    result = pytesseract.image_to_string(Image.open(image))
    if result == expected_text:
        LOGGER.info('%s: Captcha is insecure, \
Details: Expected=%s, Reversed=%s', show_open(), expected_text, result)
        return True
    else:
        LOGGER.info('%s: Captcha is secure, \
Details: Expected=%s, Reversed=%s', show_close(), expected_text, result)
        return False


@track
def is_insecure_in_url(image_url, expected_text, *args, **kwargs):
    """Verifica si la URL es un captcha inseguro."""
    session = http_helper.HTTPSession(image_url, stream=True, *args, **kwargs)
    image = session.response.raw
    result = pytesseract.image_to_string(Image.open(image))
    if result == expected_text:
        LOGGER.info('%s: Captcha is insecure, \
Details: Expected=%s, Reversed=%s', show_open(), expected_text, result)
        return True
    else:
        LOGGER.info('%s: Captcha is secure, \
Details: Expected=%s, Reversed=%s', show_close(), expected_text, result)
        return False
