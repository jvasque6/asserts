# -*- coding: utf-8 -*-

"""This module allows to check PDF vulnerabilities."""

# standard imports
# None

# 3rd party imports
from PyPDF2 import PdfFileReader

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


def _has_attribute(filename: str, metaname: str) -> bool:
    """
    Check if ``docinfo`` attribute is present.

    :param filename: Path to the ``PDF`` file.
    :param metaname: Name of the attribute to search.
    """
    input_pdf = PdfFileReader(open(filename, 'rb'))
    pdf_docinfo = input_pdf.getDocumentInfo()
    metavalue = getattr(pdf_docinfo, metaname)
    if metavalue is not None:
        show_open('{} metadata in {}'.format(metaname, filename),
                  details=dict(value=str(metavalue)))

        result = True
    else:
        show_close('{} metadata in {}'.format(metaname, filename))
        result = False
    return result


@track
def has_creator(filename: str) -> bool:
    """
    Check if ``creator`` attribute is present.

    :param filename: Path to the ``PDF`` file.
    """
    return _has_attribute(filename, 'creator')


@track
def has_producer(filename: str) -> bool:
    """
    Check if ``producer`` attribute is present.

    :param filename: Path to the ``PDF`` file.
    """
    return _has_attribute(filename, 'producer')


@track
def has_author(filename: str) -> bool:
    """
    Check if ``author`` attribute is present.

    :param filename: Path to the ``PDF`` file.
    """
    return _has_attribute(filename, 'author')


# def has_create_date(filename):
#    __has_attribute(filename, "/Create Date")

# def has_modify_date(filename):
#    __has_attribute(filename, "/Modify Date")

# def has_tagged(filename):
#    __has_attribute(filename, "/Tagged PDF")

# def has_language(filename):
#    __has_attribute(filename, "/Language")
