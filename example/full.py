#/usr/bin/python

from fluidasserts.system import linux_generic
from fluidasserts.system import windows_server_2008_plus
from fluidasserts.format import string
#from fluidasserts.format import cookie
from fluidasserts.format import html
from fluidasserts.format import pdf
from fluidasserts.service import smtp
#from fluidasserts.service import webservices
from fluidasserts.service import dns
from fluidasserts.service import tcp
from fluidasserts.service import http
from fluidasserts.service import ssl
from fluidasserts.service import ldap
from fluidasserts.service import ftp


#linux_generic.is_os_min_priv_disabled(server, username, password, ssh_config=None)
#linux_generic.is_os_sudo_disabled(server, username, password, ssh_config=None)
#linux_generic.is_os_compilers_installed(server, username, password,
#linux_generic.is_os_antimalware_not_installed(server, username, password,
#linux_generic.is_os_remote_admin_enabled(server, username, password,
#linux_generic.is_os_syncookies_disabled(server, username, password,

#windows_server_2008_plus.is_os_compilers_installed(server, username, password)
#windows_server_2008_plus.is_os_antimalware_not_installed(server, username, password)
#windows_server_2008_plus.is_os_syncookies_disabled(server)
#windows_server_2008_plus.is_protected_users_disabled(server, username, password)

#password = 'uso4Suzi'
#string.is_user_password_insecure(password)
#string.is_system_password_insecure(password)
otp = '123456'
string.is_otp_token_insecure(otp)

#ssid = 'FLUID'
#string.is_ssid_insecure(ssid)

#cookie.has_not_http_only(url, cookie_name)
#cookie.has_not_secure(url, cookie_name)

#html.has_not_autocomplete(filename, selector)
#html.is_cacheable(filename)

#pdf.has_creator(filename)
#pdf.has_producer(filename)
#pdf.has_author(filename)

server = 'aspmx.l.google.com'
smtp.has_vrfy(server, port=25)

#webservices.soap_is_enable(wsdl)

domain = 'fluid.la'
nameserver = 'ns-79.awsdns-09.com.'
dns.is_xfr_enabled(domain, nameserver)
dns.is_dynupdate_enabled(domain, nameserver)
dns.has_cache_poison(domain, nameserver)
dns.has_cache_snooping(nameserver)
dns.has_recursion(nameserver)

server = 'fluid.la'
tcp.is_port_open(server, port=3389)

site = 'fluid.la'
ssl.is_cert_cn_not_equal_to_site(site, port=443)
ssl.is_cert_inactive(site, port=443)
ssl.is_cert_validity_lifespan_unsafe(site, port=443)
ssl.is_pfs_disabled(site, port=443)
ssl.is_sslv3_enabled(site, port=443)
ssl.is_tlsv1_enabled(site, port=443)

#ldap.is_anonymous_bind_allowed(ldap_server, port=PORT)

#ftp.is_a_valid_user(ip_address, username, password, port=PORT)
#ftp.user_without_password(ip_address, username)
#ftp.is_anonymous_enabled(ip_address)
#ftp.is_admin_enabled(ip_address, password, username=ADMIN_USERNAME)
#ftp.is_version_visible(ip_address, port=PORT)

url = 'https://fluid.la'
http.is_header_x_asp_net_version_missing(url)
http.is_header_access_control_allow_origin_missing(url)
http.is_header_cache_control_missing(url)
http.is_header_content_security_policy_missing(url)
http.is_header_content_type_missing(url)
http.is_header_expires_missing(url)
http.is_header_pragma_missing(url)
http.is_header_server_insecure(url)
http.is_header_x_content_type_options_missing(url)
http.is_header_x_frame_options_missing(url)
http.is_header_perm_cross_dom_pol_missing(url)
http.is_header_x_xxs_protection_missing(url)
http.is_header_hsts_missing(url)
http.is_basic_auth_enabled(url)
http.has_trace_method(url)
http.has_delete_method(url)
http.has_put_method(url)
#http.has_sqli(url, expect=None, params=None, data='', cookies=None)
#http.has_xss(url, expect, params=None, data='', cookies=None)
#http.has_command_injection(url, expect, params=None, data='', cookies=None)
#http.has_php_command_injection(url, expect, params=None, data='', cookies=None)
#http.has_session_fixation(url, expect, params=None, data='')
#http.has_insecure_dor(url, expect, params=None, data='', cookies=None)
#http.has_dirtraversal(url, expect, params=None, data='', cookies=None)
#http.has_csrf(url, expect, params=None, data='', cookies=None)
#http.has_lfi(url, expect, params=None, data='', cookies=None)
#http.has_hpp(url, expect, params=None, data='', cookies=None)
#http.has_insecure_upload(url, expect, file_param, file_path, params=None,
http.is_sessionid_exposed(url)
server = 'fluid.la'
http.is_version_visible(server, port=80)
http.is_version_visible(server, ssl=True, port=443)
