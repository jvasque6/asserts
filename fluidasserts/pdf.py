# -*- coding: utf-8 -*-

"""Modulo para verificación del formato PDF.

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


def __has_attribute(filename, metaname):
    """Verifica si un atributo docinfo se encuentra en el PDF"""
    input_pdf = PdfFileReader(open(filename, 'rb'))
    pdf_docinfo = input_pdf.getDocumentInfo()
    metavalue = getattr(pdf_docinfo, metaname)
    if metavalue is not None:
        logging.info('%s metadata in %s, Details=%s, %s',
                     metaname, filename, metavalue, 'OPEN')
        result = True
    else:
        logging.info('%s metadata in %s, Details=%s, %s',
                     metaname, filename, '', 'CLOSE')
        result = False
    return result


def has_creator(filename):
    """Verifica si el PDF tiene el atributo creator en la sección docinfo"""
    return __has_attribute(filename, 'creator')


def has_producer(filename):
    """Verifica si el PDF tiene el atributo producer en la sección docinfo"""
    return __has_attribute(filename, 'producer')


def has_author(filename):
    """Verifica si el PDF tiene el atributo author en la sección docinfo"""
    return __has_attribute(filename, 'author')


# def has_create_date(filename):
#    __has_attribute(filename, "/Create Date")

# def has_modify_date(filename):
#    __has_attribute(filename, "/Modify Date")

# def has_tagged(filename):
#    __has_attribute(filename, "/Tagged PDF")

# def has_language(filename):
#    __has_attribute(filename, "/Language")
