import logging 
from pyPdf import PdfFileReader

def __has_attribute(filename, metaname):
    pdf_toread = PdfFileReader(open(filename, "rb"))
    pdf_info = pdf_toread.getDocumentInfo()
    try:
        metavalue = pdf_info[metaname]
        logging.info('%s metadata in %s, Details=%s, %s', metaname, filename, metavalue, 'OPEN')
    except KeyError, e:
        logging.info('%s metadata in %s, Details=%s, %s', metaname, filename, '', 'CLOSE')

def has_creator(filename):
    __has_attribute(filename, "/Creator")

def has_producer(filename):
    __has_attribute(filename, "/Producer")

def has_author(filename):
    __has_attribute(filename, "/Author")

def has_create_date(filename):
    __has_attribute(filename, "/Create Date")

def has_modify_date(filename):
    __has_attribute(filename, "/Modify Date")

def has_tagged(filename):
    __has_attribute(filename, "/Tagged PDF")

def has_language(filename):
    __has_attribute(filename, "/Language")

