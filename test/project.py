from fluidasserts import pdf

pdf.has_author('test/data/vulnerable.pdf')
pdf.has_creator('test/data/vulnerable.pdf')
pdf.has_producer('test/data/vulnerable.pdf')

pdf.has_author('test/data/non-vulnerable.pdf')
pdf.has_creator('test/data/non-vulnerable.pdf')
pdf.has_producer('test/data/non-vulnerable.pdf')

