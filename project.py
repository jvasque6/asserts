from fluidasserts import pdf
##from fluidasserts import http
##from fluidasserts import cookie

pdf.has_author('tests/data/vulnerable.pdf')
pdf.has_creator('tests/data/vulnerable.pdf')
pdf.has_producer('tests/data/vulnerable.pdf')
# pendiente incluir soporte de metadata xdf
#pdf.has_create_date('test/vulnerable.pdf')
#pdf.has_modify_date('test/vulnerable.pdf')
#pdf.has_tagged('test/vulnerable.pdf')
#pdf.has_language('test/vulnerable.pdf')

pdf.has_author('tests/data/non-vulnerable.pdf')
pdf.has_creator('tests/data/non-vulnerable.pdf')
pdf.has_producer('tests/data/non-vulnerable.pdf')
# pendiente incluir soporte de metadata xdf
#pdf.has_create_date('test/non-vulnerable.pdf')
#pdf.has_modify_date('test/non-vulnerable.pdf')
#pdf.has_tagged('test/non-vulnerable.pdf')
#pdf.has_language('test/non-vulnerable.pdf')

#http.has_header_x_xxs_protection("http://localhost/cursos")
#http.has_header_x_xxs_protection("http://challengeland.co/")
#http.has_header_x_frame_options("http://localhost/cursos")
#http.has_header_x_frame_options("http://challengeland.co/")
#http.has_header_x_permitted_cross_domain_policies("http://localhost/cursos")
#http.has_header_x_permitted_cross_domain_policies("http://challengeland.co/")
#http.has_header_x_content_type_options("http://localhost/cursos")
#http.has_header_x_content_type_options("http://challengeland.co")
#http.has_header_pragma("http://localhost/cursos")
#http.has_header_pragma("http://challengeland.co")
#http.has_header_expires("http://localhost/cursos")
#http.has_header_expires("http://challengeland.co")
#http.has_header_pragma("http://localhost/cursos")
#http.has_header_content_type("http://challengeland.co")
#http.has_header_content_security_policy("http://challengeland.co")
#http.has_header_content_security_policy("http://localhost/cursos")
#http.has_header_cache_control("http://localhost/cursos")
#http.has_header_cache_control("http://challengeland.co")
#http.has_header_access_control_allow_origin("http://localhost/cursos")
#http.has_header_access_control_allow_origin("http://challengeland.co")

#cookie.has_http_only("http://challengeland.co","ci_session")
#http.basic_auth("http://localhost/fluidopens/BasicAuth/","root","1234")
#http.basic_auth("http://localhost/fluidopens/BasicAuth/","Admin","1234")
