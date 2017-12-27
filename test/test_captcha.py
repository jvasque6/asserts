# -*- coding: utf-8 -*-

"""Modulo para pruebas de captcha."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.format import captcha

# Constants
SECURE_CAPTCHA_IMG = ['test/provision/captcha/secure.jpg', '504375']
WEAK_CAPTCHA_IMG = ['test/provision/captcha/weak.jpg', 'WORDS']


#
# Open tests
#


def test_is_insecure_in_image_open():
    """Insecure captcha open"""
    assert captcha.is_insecure_in_image(WEAK_CAPTCHA_IMG[0],
                                        WEAK_CAPTCHA_IMG[1])


#
# Closing tests
#


def test_is_insecure_in_image_close():
    """Insecure captcha close"""
    assert not captcha.is_insecure_in_image(SECURE_CAPTCHA_IMG[0],
                                            SECURE_CAPTCHA_IMG[1])
