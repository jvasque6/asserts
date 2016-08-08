import pytest
from fluidasserts import pdf

def test_pdf_has_author_open():
    assert True == pdf.has_author('tests/data/vulnerable.pdf')

def test_pdf_has_creator_open():
    assert True == pdf.has_creator('tests/data/vulnerable.pdf')

def test_pdf_has_producer_open():
    assert True == pdf.has_producer('tests/data/vulnerable.pdf')

def test_pdf_has_author_close():
    assert False == pdf.has_author('tests/data/non-vulnerable.pdf')

def test_pdf_has_creator_close():
    assert False == pdf.has_creator('tests/data/non-vulnerable.pdf')

def test_pdf_has_producer_close():
    assert False == pdf.has_producer('tests/data/non-vulnerable.pdf')

# pendiente incluir soporte de metadata xdf
#pdf.has_create_date('test/vulnerable.pdf')
#pdf.has_modify_date('test/vulnerable.pdf')
#pdf.has_tagged('test/vulnerable.pdf')
#pdf.has_language('test/vulnerable.pdf')

# pendiente incluir soporte de metadata xdf
#pdf.has_create_date('test/non-vulnerable.pdf')
#pdf.has_modify_date('test/non-vulnerable.pdf')
#pdf.has_tagged('test/non-vulnerable.pdf')
#pdf.has_language('test/non-vulnerable.pdf')
