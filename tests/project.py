###<<<<<<< HEAD
##from fluidasserts import pdf
##from fluidasserts import http
##from fluidasserts import cookie
from fluidasserts import smtp
"""
=======
from fluidasserts import pdf
#from fluidasserts import http
#from fluidasserts import cookie

>>>>>>> d3ff5727445c68be9e920574b9429dd84a392a51
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
<<<<<<< HEAD
"""
#smtp.has_vrfy('127.0.0.1', 25)


# javascript module
#js.is_obfuscated('Admin.js')

# html module
# using elementtree 
# http://stackoverflow.com/questions/8692/how-to-use-xpath-in-python 
# http://effbot.org/zone/element-xpath.htm
#html.no_autocomplete('Archivo.html', 'dom.location.dsdf.sd.fdf')

# ssl module or x509 module?
# using twisted
# http://stackoverflow.com/questions/1087227/validate-ssl-certificates-with-python
# http://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
# http://pyopenssl.sourceforge.net/pyOpenSSL.html/openssl-x509.html
# https://www.sslshopper.com/ssl-checker.html#hostname=https://fluid.la
# ssl.is_self_signed()
# ssl.has_expired()
# ssl.expires_soon(asdsd, days)
# ssl.resolved_accordinly 

# http module
# pruebas asimetricas
# http.response_is_stable(seconds, URL, repeat)

# tcp.is_open(ip, port)

# ssh module
# ssh.has_advisory()
# ssh.is_open()
# ssh.

# ldap module
# ldap.is_open(ip)
# ldap.supports_anonymous_connection()

# ftp module
# ftp.is_open(ip)
# ftp.supports_anonymous_connection(ip)

# smtp module
# smtp.is_open()
# smtp.supports_anonymous_connection(ip)

# dns module
# dns.is_open()
# dns.zone_transfer()

# voip??
##>>>>>>> d3ff5727445c68be9e920574b9429dd84a392a51
