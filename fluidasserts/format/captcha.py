# -*- coding: utf-8 -*-

"""This module allows to check ``CAPTCHA`` vulnerabilities."""


# standard imports
from PIL import Image

# 3rd party imports
import pytesseract

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper import http
from fluidasserts.utils.decorators import track, level, notify


@notify
@level('medium')
@track
def is_insecure_in_image(image: str, expected_text: str) -> bool:
    """
    Check if the given image is an insecure CAPTCHA.

    The check is performed by converting the image to text and
    comparing with the given expected text.

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


@notify
@level('medium')
@track
def is_insecure_in_url(image_url: str, expected_text: str,
                       *args, **kwargs) -> bool:
    r"""
    Check if the image in the URL is an insecure CAPTCHA.

    The check is performed by converting the image to text and
    comparing with the given expected text.

    :param image_url: Path to the image to be tested.
    :param expected_text: Text the image might contain.
    :param \*args: Optional positional arguments for
        :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
        :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    session = http.HTTPSession(image_url, stream=True, *args, **kwargs)
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
