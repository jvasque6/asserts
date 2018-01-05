# -*- coding: utf-8 -*-

"""Modulo para verificacion del formato PDF.

Este modulo permite verificar vulnerabilidades que se encuentran en un archivo
con formato PDF.  Algunas de ellas son:

    * Metadatos docinfo,
    * Metadatos XDF.
"""

# standard imports
import logging

# 3rd party imports
from PyPDF2 import PdfFileReader

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track

LOGGER = logging.getLogger('FLUIDAsserts')


def __has_attribute(filename, metaname):
    """Verifica si un atributo docinfo se encuentra en el PDF."""
    input_pdf = PdfFileReader(open(filename, 'rb'))
    pdf_docinfo = input_pdf.getDocumentInfo()
    metavalue = getattr(pdf_docinfo, metaname)
    if metavalue is not None:
        LOGGER.info('%s: %s metadata in %s, Details=%s',
                    show_open(), metaname, filename, metavalue)
        result = True
    else:
        LOGGER.info('%s: %s metadata in %s, Details=%s',
                    show_close(), metaname, filename, '')
        result = False
    return result


@track
def has_creator(filename):
    """Verifica si el PDF tiene el atributo creator en la seccion docinfo."""
    return __has_attribute(filename, 'creator')


@track
def has_producer(filename):
    """Verifica si el PDF tiene el atributo producer en la seccion docinfo."""
    return __has_attribute(filename, 'producer')


@track
def has_author(filename):
    """Verifica si el PDF tiene el atributo author en la seccion docinfo."""
    return __has_attribute(filename, 'author')


# def has_create_date(filename):
#    __has_attribute(filename, "/Create Date")

# def has_modify_date(filename):
#    __has_attribute(filename, "/Modify Date")

# def has_tagged(filename):
#    __has_attribute(filename, "/Tagged PDF")

# def has_language(filename):
#    __has_attribute(filename, "/Language")
