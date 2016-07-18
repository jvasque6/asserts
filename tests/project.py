from fluidasserts import pdf

pdf.has_author('tests/data/vulnerable.pdf')
pdf.has_creator('tests/data/vulnerable.pdf')
pdf.has_producer('tests/data/vulnerable.pdf')
#pdf.has_create_date('test/vulnerable.pdf')
#pdf.has_modify_date('test/vulnerable.pdf')
#pdf.has_tagged('test/vulnerable.pdf')
#pdf.has_language('test/vulnerable.pdf')

pdf.has_author('tests/data/non-vulnerable.pdf')
pdf.has_creator('tests/data/non-vulnerable.pdf')
pdf.has_producer('tests/data/non-vulnerable.pdf')
#pdf.has_create_date('test/non-vulnerable.pdf')
#pdf.has_modify_date('test/non-vulnerable.pdf')
#pdf.has_tagged('test/non-vulnerable.pdf')
#pdf.has_language('test/non-vulnerable.pdf')

