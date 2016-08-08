import logging 
from PyPDF2 import PdfFileReader

def __has_attribute(filename, metaname):
    input_pdf = PdfFileReader(open(filename, "rb"))
    pdf_docinfo = input_pdf.getDocumentInfo()
    metavalue = getattr(pdf_docinfo, metaname)
    if metavalue != None:
        logging.info('%s metadata in %s, Details=%s, %s', metaname, filename, metavalue, 'OPEN')
        result = True
    else:
        logging.info('%s metadata in %s, Details=%s, %s', metaname, filename, '', 'CLOSE')
        result = False
    return result

def has_creator(filename):
    return __has_attribute(filename, 'creator')

def has_producer(filename):
    return __has_attribute(filename, 'producer')

def has_author(filename):
    return __has_attribute(filename, 'author')


#def has_create_date(filename):
#    __has_attribute(filename, "/Create Date")

#def has_modify_date(filename):
#    __has_attribute(filename, "/Modify Date")

#def has_tagged(filename):
#    __has_attribute(filename, "/Tagged PDF")

#def has_language(filename):
#    __has_attribute(filename, "/Language")

