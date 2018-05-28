# -*- coding: utf-8 -*-

"""
CAPTCHA module.

This module allows to check ``CAPTCHA`` vulnerabilities.
"""


# standard imports
from PIL import Image

# 3rd party imports
import pytesseract

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper import http_helper
from fluidasserts.utils.decorators import track


@track
def is_insecure_in_image(image: str, expected_text: str) -> bool:
    """
    Check if the image is an insecure CAPTCHA.

    :param image: Path to the image to be tested.
    :param expected_text: Text the image might contain.
    """
    result = pytesseract.image_to_string(Image.open(image))
    if result == expected_text:
        show_open('Captcha is insecure',
                  details=dict(expected=expected_text, reversed=result))
        return True
    show_close('Captcha is secure',
               details=dict(expected=expected_text, reversed=result))
    return False


@track
def is_insecure_in_url(image_url: str, expected_text: str,
                       *args, **kwargs) -> bool:
    r"""
    Check if the URL is an insecure CAPTCHA.

    :param image_url: Path to the image to be tested.
    :param expected_text: Text the image might contain.
    :param \*args: Optional positional arguments for
        :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
        :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    """
    session = http_helper.HTTPSession(image_url, stream=True, *args, **kwargs)
    fingerprint = session.get_fingerprint()
    image = session.response.raw
    result = pytesseract.image_to_string(Image.open(image))
    if result == expected_text:
        show_open('Captcha is insecure',
                  details=dict(expected=expected_text, reversed=result,
                               fingerprint=fingerprint))
        return True
    show_close('Captcha is secure',
               details=dict(expected=expected_text, reversed=result,
                            fingerprint=fingerprint))
    return False
