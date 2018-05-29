#/usr/bin/python

from fluidasserts.system import linux_generic
from fluidasserts.system import win_server
from fluidasserts.format import string
from fluidasserts.format import x509
#from fluidasserts.format import cookie
from fluidasserts.lang import html
from fluidasserts.format import pdf
from fluidasserts.proto import smtp
#from fluidasserts.proto import webservices
from fluidasserts.proto import dns
from fluidasserts.proto import tcp
from fluidasserts.proto import http
from fluidasserts.proto import ssl
from fluidasserts.proto import ldap
from fluidasserts.proto import ftp


#linux_generic.is_os_min_priv_disabled(server, username, password, ssh_config=None)
#linux_generic.is_os_sudo_disabled(server, username, password, ssh_config=None)
#linux_generic.is_os_compilers_installed(server, username, password,
#linux_generic.is_os_antimalware_not_installed(server, username, password,
#linux_generic.is_os_remote_admin_enabled(server, username, password,
#linux_generic.is_os_syncookies_disabled(server, username, password,

#win_server.is_os_compilers_installed(server, username, password)
#win_server.is_os_antimalware_not_installed(server, username, password)
#win_server.is_os_syncookies_disabled(server)
#win_server.is_protected_users_disabled(server, username, password)

#password = 'uso4Suzi'
#string.is_user_password_insecure(password)
#string.is_system_password_insecure(password)
otp = '123456'
string.is_otp_token_insecure(otp)

#ssid = 'FLUID'
#string.is_ssid_insecure(ssid)

#cookie.has_not_http_only(url, cookie_name)
#cookie.has_not_secure(url, cookie_name)

#html.has_not_autocomplete(filename)
#html.is_cacheable(filename)

#pdf.has_creator(filename)
#pdf.has_producer(filename)
#pdf.has_author(filename)

server = 'aspmx.l.google.com'
smtp.has_vrfy(server, port=25)

#webservices.soap_is_enable(wsdl)

domain = 'fluidattacks.com'
nameserver = '205.251.192.79'
dns.is_xfr_enabled(domain, nameserver)
dns.is_dynupdate_enabled(domain, nameserver)
dns.has_cache_poison(domain, nameserver)
dns.has_cache_snooping(nameserver)
dns.has_recursion(nameserver)

server = 'fluidattacks.com'
tcp.is_port_open(server, port=3389)

host = 'fluidattacks.com'
ssl.allows_anon_ciphers(host,port=443)
ssl.allows_weak_ciphers(host,port=443)
ssl.has_beast(host,port=443)
ssl.has_breach(host,port=443)
ssl.has_heartbleed(host,port=443)
ssl.has_poodle_sslv3(host,port=443)
ssl.has_poodle_tls(host,port=443)
ssl.is_pfs_disabled(host,port=443)
ssl.is_sslv3_enabled(host,port=443)
ssl.is_tlsv1_enabled(host,port=443)
x509.is_sha1_used(host,port=443)
x509.is_md5_used(host,port=443)
x509.is_cert_cn_not_equal_to_site(host,port=443)
x509.is_cert_inactive(host,port=443)
x509.is_cert_validity_lifespan_unsafe(host,port=443)

#ldap.is_anonymous_bind_allowed(ldap_server, port=PORT)

#ftp.is_a_valid_user(ip_address, username, password, port=PORT)
#ftp.user_without_password(ip_address, username)
#ftp.is_anonymous_enabled(ip_address)
#ftp.is_admin_enabled(ip_address, password, username=ADMIN_USERNAME)
#ftp.is_version_visible(ip_address, port=PORT)

url = 'https://fluidattacks.com'
http.is_header_x_asp_net_version_present(url)
http.is_header_access_control_allow_origin_missing(url)
http.is_header_cache_control_missing(url)
http.is_header_content_security_policy_missing(url)
http.is_header_content_type_missing(url)
http.is_header_expires_missing(url)
http.is_header_pragma_missing(url)
http.is_header_server_present(url)
http.is_header_x_content_type_options_missing(url)
http.is_header_x_frame_options_missing(url)
http.is_header_perm_cross_dom_pol_missing(url)
http.is_header_x_xxs_protection_missing(url)
http.is_header_hsts_missing(url)
http.is_basic_auth_enabled(url)
http.has_trace_method(url)
http.has_delete_method(url)
http.has_put_method(url)
http.has_dirlisting('https://fluidattacks.com/icons')
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
server = 'fluidattacks.com'
http.is_version_visible(server, port=80)
http.is_version_visible(server, ssl=True, port=443)
text = 'Continuous Hacking'
http.has_not_text('https://fluidattacks.com', text)

http.is_not_https_required('http://fluidattacks.com')
