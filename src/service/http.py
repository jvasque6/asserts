# -*- coding: utf-8 -*-

"""Modulo para verificacion del protocolo HTTP.

Este modulo permite verificar vulnerabilidades propias de HTTP como:

    * Transporte plano de informacion,
    * Headers de seguridad no establecidos,
    * Cookies no generadas de forma segura,
"""

# standard imports
import logging
import re

# 3rd party imports
# None

# local imports
from fluidasserts.helper import banner_helper
from fluidasserts.helper import http_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track

logger = logging.getLogger('FLUIDAsserts')

# Regex taken from SQLmap project
SQLI_ERROR_MSG = {
    'SQL syntax.*MySQL',  # MySQL
    'Warning.*mysql_.*',  # MySQL
    'MySqlException \(0x',  # MySQL
    'valid MySQL result',  # MySQL
    'check the manual that corresponds to your (MySQL|MariaDB) server version',  # MySQL
    'MySqlClient.',  # MySQL
    'com.mysql.jdbc.exceptions',  # MySQL
    'com.mysql.jdbc.exceptions',  # PostgreSQL
    'PostgreSQL.*ERROR',  # PostgreSQL
    'Warning.*Wpg_.*',  # PostgreSQL
    'valid PostgreSQL result',  # PostgreSQL
    'Npgsql.',  # PostgreSQL
    'PG::SyntaxError:',  # PostgreSQL
    'org.postgresql.util.PSQLException',  # PostgreSQL
    'ERROR:sssyntax error at or near ',  # PostgreSQL
    'ERROR:sssyntax error at or near ',  # Microsoft SQL Server
    'Driver.* SQL[-_ ]*Server',  # Microsoft SQL Server
    'OLE DB.* SQL Server',  # Microsoft SQL Server
    '\bSQL Server[^&lt;&quot;]+Driver',  # Microsoft SQL Server
    'Warning.*(mssql|sqlsrv)_',  # Microsoft SQL Server
    '\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}',  # Microsoft SQL Server
    'System.Data.SqlClient.SqlException',  # Microsoft SQL Server
    '(?s)Exception.*WRoadhouse.Cms.',  # Microsoft SQL Server
    'Microsoft SQL Native Client error \'[0-9a-fA-F]{8}',  # Microsoft SQL Server
    'com.microsoft.sqlserver.jdbc.SQLServerException',  # Microsoft SQL Server
    'ODBC SQL Server Driver',  # Microsoft SQL Server
    'SQLServer JDBC Driver',  # Microsoft SQL Server
    'macromedia.jdbc.sqlserver',  # Microsoft SQL Server
    'com.jnetdirect.jsql',  # Microsoft SQL Server
    'com.jnetdirect.jsql',  # Microsoft Access
    'Microsoft Access (d+ )?Driver',  # Microsoft Access
    'JET Database Engine',  # Microsoft Access
    'Access Database Engine',  # Microsoft Access
    'ODBC Microsoft Access',  # Microsoft Access
    'Syntax error (missing operator) in query expression',  # Microsoft Access
    'Syntax error (missing operator) in query expression',  # Oracle
    '\bORA-d{5}',  # Oracle
    'Oracle error',  # Oracle
    'Oracle.*Driver',  # Oracle
    'Warning.*Woci_.*',  # Oracle
    'Warning.*Wora_.*',  # Oracle
    'oracle.jdbc.driver',  # Oracle
    'quoted string not properly terminated',  # Oracle
    'quoted string not properly terminated',  # IBM DB2
    'CLI Driver.*DB2',  # IBM DB2
    'DB2 SQL error',  # IBM DB2
    '\bdb2_w+\(',  # IBM DB2
    'SQLSTATE.+SQLCODE',  # IBM DB2
    'SQLSTATE.+SQLCODE',  # Informix
    'Exception.*Informix',  # Informix
    'Informix ODBC Driver',  # Informix
    'com.informix.jdbc',  # Informix
    'weblogic.jdbc.informix',  # Informix
    'weblogic.jdbc.informix',  # Firebird
    'Dynamic SQL Error',  # Firebird
    'Warning.*ibase_.*',  # Firebird
    'Warning.*ibase_.*',  # SQLite
    'SQLite/JDBCDriver',  # SQLite
    'SQLite.Exception',  # SQLite
    'System.Data.SQLite.SQLiteException',  # SQLite
    'Warning.*sqlite_.*',  # SQLite
    'Warning.*SQLite3::',  # SQLite
    '\[SQLITE_ERROR\]',  # SQLite
    '\[SQLITE_ERROR\]',  # SAP MaxDB
    'SQL error.*POS([0-9]+).*',  # SAP MaxDB
    'Warning.*maxdb.*',  # SAP MaxDB
    'Warning.*maxdb.*',  # Sybase
    'Warning.*sybase.*',  # Sybase
    'Sybase message',  # Sybase
    'Sybase.*Server message.*',  # Sybase
    'SybSQLException',  # Sybase
    'com.sybase.jdbc',  # Sybase
    'com.sybase.jdbc',  # Ingres
    'Warning.*ingres_',  # Ingres
    'Ingres SQLSTATE',  # Ingres
    'IngresW.*Driver',  # Ingres
    'IngresW.*Driver',  # Frontbase
    'Exception (condition )?d+. Transaction rollback.',  # Frontbase
    'Exception (condition )?d+. Transaction rollback.',  # HSQLDB
    'org.hsqldb.jdbc',  # HSQLDB
    'Unexpected end of command in statement \[',  # HSQLDB
    'Unexpected token.*in statement \[',  # HSQLDB
}


# pylint: disable=R0913
def __generic_http_assert(url, expected_regex, *args, **kwargs):
    """Generic HTTP assert method."""
    http_session = http_helper.HTTPSession(url, *args, **kwargs)
    response = http_session.response
    the_page = response.text

    if re.search(str(expected_regex), the_page, re.IGNORECASE):
        return True
    return False


# pylint: disable=R0913
def __multi_generic_http_assert(url, regex_list, *args, **kwargs):
    """Generic HTTP assert method."""
    http_session = http_helper.HTTPSession(url, *args, **kwargs)
    response = http_session.response
    the_page = response.text

    for regex in regex_list:
        if re.search(regex, the_page, re.IGNORECASE):
            return regex
    return False


@track
def has_multiple_text(url, regex_list, *args, **kwargs):
    """Check if a bad text is present."""
    ret = __multi_generic_http_assert(url, regex_list, *args, **kwargs)
    if ret:
        logger.info('%s: %s Bad text present, Details=%s',
                    show_open(), url, ret)
        return True
    logger.info('%s: %s Bad text not present', show_close(), url)
    return False


@track
def has_text(url, expected_text, *args, **kwargs):
    """Check if a bad text is present."""
    ret = __generic_http_assert(url, expected_text, *args, **kwargs)
    if ret:
        logger.info('%s: %s Bad text present, Details=%s',
                    show_open(), url, expected_text)
        return True
    logger.info('%s: %s Bad text not present, Details=%s',
                show_close(), url, expected_text)
    return False


@track
def has_not_text(url, expected_text, *args, **kwargs):
    """Check if a required text is not present."""
    ret = __generic_http_assert(url, expected_text, *args, **kwargs)
    if not ret:
        logger.info('%s: %s Expected text not present, Details=%s',
                    show_open(), url, expected_text)
        return True
    logger.info('%s: %s Expected text present, Details=%s',
                show_close(), url, expected_text)
    return False


@track
def is_header_x_asp_net_version_missing(url, *args, **kwargs):
    """Check if x-aspnet-version header is missing."""
    return http_helper.has_insecure_header(url, 'X-AspNet-Version',
                                           *args, **kwargs)


@track
def is_header_access_control_allow_origin_missing(url, *args, **kwargs):
    """Check if access-control-allow-origin header is missing."""
    return http_helper.has_insecure_header(url,
                                           'Access-Control-Allow-Origin',
                                           *args, **kwargs)


@track
def is_header_cache_control_missing(url, *args, **kwargs):
    """Check if cache-control header is missing."""
    return http_helper.has_insecure_header(url, 'Cache-Control',
                                           *args, **kwargs)


@track
def is_header_content_security_policy_missing(url, *args, **kwargs):
    """Check if content-security-policy header is missing."""
    return http_helper.has_insecure_header(url,
                                           'Content-Security-Policy',
                                           *args, **kwargs)


@track
def is_header_content_type_missing(url, *args, **kwargs):
    """Check if content-security-policy header is missing."""
    return http_helper.has_insecure_header(url, 'Content-Type',
                                           *args, **kwargs)


@track
def is_header_expires_missing(url, *args, **kwargs):
    """Check if content-security-policy header is missing."""
    return http_helper.has_insecure_header(url, 'Expires',
                                           *args, **kwargs)


@track
def is_header_pragma_missing(url, *args, **kwargs):
    """Check if pragma header is missing."""
    return http_helper.has_insecure_header(url, 'Pragma',
                                           *args, **kwargs)


@track
def is_header_server_insecure(url, *args, **kwargs):
    """Check if server header is insecure."""
    return http_helper.has_insecure_header(url, 'Server',
                                           *args, **kwargs)


@track
def is_header_x_content_type_options_missing(url, *args, **kwargs):
    """Check if x-content-type-options header is missing."""
    return http_helper.has_insecure_header(url,
                                           'X-Content-Type-Options',
                                           *args, **kwargs)


@track
def is_header_x_frame_options_missing(url, *args, **kwargs):
    """Check if x-frame-options header is missing."""
    return http_helper.has_insecure_header(url, 'X-Frame-Options',
                                           *args, **kwargs)


@track
def is_header_perm_cross_dom_pol_missing(url, *args, **kwargs):
    """Check if permitted-cross-domain-policies header is missing."""
    return http_helper.has_insecure_header(url,
                                           'X-Permitted-Cross-Domain-Policies',
                                           *args, **kwargs)


@track
def is_header_x_xxs_protection_missing(url, *args, **kwargs):
    """Check if x-xss-protection header is missing."""
    return http_helper.has_insecure_header(url, 'X-XSS-Protection',
                                           *args, **kwargs)


@track
def is_header_hsts_missing(url, *args, **kwargs):
    """Check if strict-transport-security header is missing."""
    return http_helper.has_insecure_header(url,
                                           'Strict-Transport-Security',
                                           *args, **kwargs)


@track
def is_basic_auth_enabled(url, *args, **kwargs):
    """Check if BASIC authentication is enabled."""
    return http_helper.has_insecure_header(url,
                                           'WWW-Authenticate',
                                           *args, **kwargs)


@track
def has_trace_method(url):
    """Check HTTP TRACE."""
    return http_helper.has_method(url, 'TRACE')


@track
def has_delete_method(url):
    """Check HTTP DELETE."""
    return http_helper.has_method(url, 'DELETE')


@track
def has_put_method(url):
    """Check HTTP PUT."""
    return http_helper.has_method(url, 'PUT')


@track
def has_sqli(url, *args, **kwargs):
    """Check SQLi vuln by checking expected string."""
    expect = SQLI_ERROR_MSG

    return has_multiple_text(url, expect, *args, **kwargs)


@track
def has_xss(url, expect, *args, **kwargs):
    """Check XSS vuln by checking expected string."""
    return has_text(url, expect,  *args, **kwargs)


@track
def has_command_injection(url, expect, *args, **kwargs):
    """Check command injection vuln by checking expected string."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_php_command_injection(url, expect, *args, **kwargs):
    """Check PHP command injection by checking expected string."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_session_fixation(url, expect, *args, **kwargs):
    """Check session fixation by no passing cookies and authenticating."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_insecure_dor(url, expect, *args, **kwargs):
    """Check insecure direct object reference vuln."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_dirtraversal(url, expect, *args, **kwargs):
    """Check directory traversal vuln by checking expected string."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_csrf(url, expect, *args, **kwargs):
    """Check CSRF vuln by checking expected string."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_lfi(url, expect, *args, **kwargs):
    """Check local file inclusion vuln by checking expected string."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_hpp(url, expect, *args, **kwargs):
    """Check HTTP Parameter Pollution vuln."""
    return has_text(url, expect, *args, **kwargs)


@track
def has_insecure_upload(url, expect, file_param, file_path, params=None,
                        data='', cookies=None):
    """Check insecure upload vuln."""
    exploit_file = {file_param: open(file_path)}
    return has_text(url, expect, params=params, data=data,
                    files=exploit_file, cookies=cookies)


@track
def is_sessionid_exposed(url, argument='sessionid', *args, **kwargs):
    """Check if resulting URL has a session ID exposed."""
    http_session = http_helper.HTTPSession(url, *args, **kwargs)
    response_url = http_session.response.url

    regex = r'\b' + argument + r'\b'

    result = True
    if re.search(regex, response_url):
        result = True
        logger.info('%s: Session ID is exposed in %s, Details=%s',
                    show_open(), response_url, argument)
    else:
        result = False
        logger.info('%s: Session ID is hidden in %s, Details=%s',
                    show_close(), response_url, argument)
    return result


@track
def is_version_visible(ip_address, ssl=False, port=80):
    """Check if banner is visible."""
    if ssl:
        service = banner_helper.HTTPSService()
    else:
        service = banner_helper.HTTPService()
    banner = banner_helper.get_banner(service, ip_address)
    version = banner_helper.get_version(service, banner)

    result = True
    if version:
        result = True
        logger.info('%s: HTTP version visible on %s:%s, Details=%s',
                    show_open(), ip_address, port, version)
    else:
        result = False
        logger.info('%s: HTTP version not visible on %s:%s, Details=None',
                    show_close(), ip_address, port)
    return result


@track
def is_not_https_required(url):
    """Check if HTTPS is always forced on a given url."""
    assert url.startswith('http://')
    http_session = http_helper.HTTPSession(url)
    if http_session.url.startswith('https'):
        logger.info('%s: HTTPS is forced on URL, Details=%s',
                    show_close(), http_session.url)
        return False
    logger.info('%s: HTTPS is not forced on URL, Details=%s',
                show_open(), http_session.url)
    return True


@track
def has_dirlisting(url, *args, **kwargs):
    """Check if url has directory listing enabled."""
    bad_text = 'Index of'
    return has_text(url, bad_text, *args, **kwargs)


@track
def is_response_delayed(url, *args, **kwargs):
    """
    Check if the response time is acceptable.

    Values taken from:
    https://www.nngroup.com/articles/response-times-3-important-limits/
    """

    max_response_time = 60
    http_session = http_helper.HTTPSession(url, *args, **kwargs)

    response_time = http_session.response.elapsed.total_seconds()
    delta = max_response_time - response_time

    if delta >= 0:
        logger.info('%s: Response time is acceptable for %s, Details=%s',
                    show_close(), http_session.url, str(response_time))
        return False
    logger.info('%s: Response time is not acceptable for %s, Details=%s',
                show_open(), http_session.url, str(response_time))
    return True
