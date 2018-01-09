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

LOGGER = logging.getLogger('FLUIDAsserts')

# Regex taken from SQLmap project
SQLI_ERROR_MSG = {
    r'SQL syntax.*MySQL',  # MySQL
    r'Warning.*mysql_.*',  # MySQL
    r'MySqlException \(0x',  # MySQL
    r'valid MySQL result',  # MySQL
    r'check the manual that corresponds to your (MySQL|MariaDB) server version',  # MySQL
    r'MySqlClient.',  # MySQL
    r'com.mysql.jdbc.exceptions',  # MySQL
    r'com.mysql.jdbc.exceptions',  # PostgreSQL
    r'PostgreSQL.*ERROR',  # PostgreSQL
    r'Warning.*Wpg_.*',  # PostgreSQL
    r'valid PostgreSQL result',  # PostgreSQL
    r'Npgsql.',  # PostgreSQL
    r'PG::SyntaxError:',  # PostgreSQL
    r'org.postgresql.util.PSQLException',  # PostgreSQL
    r'ERROR:sssyntax error at or near ',  # PostgreSQL
    r'ERROR:sssyntax error at or near ',  # Microsoft SQL Server
    r'Driver.* SQL[-_ ]*Server',  # Microsoft SQL Server
    r'OLE DB.* SQL Server',  # Microsoft SQL Server
    r'\bSQL Server[^&lt;&quot;]+Driver',  # Microsoft SQL Server
    r'Warning.*(mssql|sqlsrv)_',  # Microsoft SQL Server
    r'\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}',  # Microsoft SQL Server
    r'System.Data.SqlClient.SqlException',  # Microsoft SQL Server
    r'(?s)Exception.*WRoadhouse.Cms.',  # Microsoft SQL Server
    r'Microsoft SQL Native Client error \'[0-9a-fA-F]{8}',  # Microsoft SQL Server
    r'com.microsoft.sqlserver.jdbc.SQLServerException',  # Microsoft SQL Server
    r'ODBC SQL Server Driver',  # Microsoft SQL Server
    r'SQLServer JDBC Driver',  # Microsoft SQL Server
    r'macromedia.jdbc.sqlserver',  # Microsoft SQL Server
    r'com.jnetdirect.jsql',  # Microsoft SQL Server
    r'com.jnetdirect.jsql',  # Microsoft Access
    r'Microsoft Access (d+ )?Driver',  # Microsoft Access
    r'JET Database Engine',  # Microsoft Access
    r'Access Database Engine',  # Microsoft Access
    r'ODBC Microsoft Access',  # Microsoft Access
    r'Syntax error (missing operator) in query expression',  # Microsoft Access
    r'Syntax error (missing operator) in query expression',  # Oracle
    r'\bORA-d{5}',  # Oracle
    r'Oracle error',  # Oracle
    r'Oracle.*Driver',  # Oracle
    r'Warning.*Woci_.*',  # Oracle
    r'Warning.*Wora_.*',  # Oracle
    r'oracle.jdbc.driver',  # Oracle
    r'quoted string not properly terminated',  # Oracle
    r'quoted string not properly terminated',  # IBM DB2
    r'CLI Driver.*DB2',  # IBM DB2
    r'DB2 SQL error',  # IBM DB2
    r'\bdb2_w+\(',  # IBM DB2
    r'SQLSTATE.+SQLCODE',  # IBM DB2
    r'SQLSTATE.+SQLCODE',  # Informix
    r'Exception.*Informix',  # Informix
    r'Informix ODBC Driver',  # Informix
    r'com.informix.jdbc',  # Informix
    r'weblogic.jdbc.informix',  # Informix
    r'weblogic.jdbc.informix',  # Firebird
    r'Dynamic SQL Error',  # Firebird
    r'Warning.*ibase_.*',  # Firebird
    r'Warning.*ibase_.*',  # SQLite
    r'SQLite/JDBCDriver',  # SQLite
    r'SQLite.Exception',  # SQLite
    r'System.Data.SQLite.SQLiteException',  # SQLite
    r'Warning.*sqlite_.*',  # SQLite
    r'Warning.*SQLite3::',  # SQLite
    r'\[SQLITE_ERROR\]',  # SQLite
    r'\[SQLITE_ERROR\]',  # SAP MaxDB
    r'SQL error.*POS([0-9]+).*',  # SAP MaxDB
    r'Warning.*maxdb.*',  # SAP MaxDB
    r'Warning.*maxdb.*',  # Sybase
    r'Warning.*sybase.*',  # Sybase
    r'Sybase message',  # Sybase
    r'Sybase.*Server message.*',  # Sybase
    r'SybSQLException',  # Sybase
    r'com.sybase.jdbc',  # Sybase
    r'com.sybase.jdbc',  # Ingres
    r'Warning.*ingres_',  # Ingres
    r'Ingres SQLSTATE',  # Ingres
    r'IngresW.*Driver',  # Ingres
    r'IngresW.*Driver',  # Frontbase
    r'Exception (condition )?d+. Transaction rollback.',  # Frontbase
    r'Exception (condition )?d+. Transaction rollback.',  # HSQLDB
    r'org.hsqldb.jdbc',  # HSQLDB
    r'Unexpected end of command in statement \[',  # HSQLDB
    r'Unexpected token.*in statement \[',  # HSQLDB
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
        LOGGER.info('%s: %s Bad text present, Details=%s',
                    show_open(), url, ret)
        return True
    LOGGER.info('%s: %s Bad text not present', show_close(), url)
    return False


@track
def has_text(url, expected_text, *args, **kwargs):
    """Check if a bad text is present."""
    ret = __generic_http_assert(url, expected_text, *args, **kwargs)
    if ret:
        LOGGER.info('%s: %s Bad text present, Details=%s',
                    show_open(), url, expected_text)
        return True
    LOGGER.info('%s: %s Bad text not present, Details=%s',
                show_close(), url, expected_text)
    return False


@track
def has_not_text(url, expected_text, *args, **kwargs):
    """Check if a required text is not present."""
    ret = __generic_http_assert(url, expected_text, *args, **kwargs)
    if not ret:
        LOGGER.info('%s: %s Expected text not present, Details=%s',
                    show_open(), url, expected_text)
        return True
    LOGGER.info('%s: %s Expected text present, Details=%s',
                show_close(), url, expected_text)
    return False


@track
def is_header_x_asp_net_version_present(url, *args, **kwargs):
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
def is_header_server_present(url, *args, **kwargs):
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
    return has_text(url, expect, *args, **kwargs)


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
        LOGGER.info('%s: Session ID is exposed in %s, Details=%s',
                    show_open(), response_url, argument)
    else:
        result = False
        LOGGER.info('%s: Session ID is hidden in %s, Details=%s',
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
        LOGGER.info('%s: HTTP version visible on %s:%s, Details=%s',
                    show_open(), ip_address, port, version)
    else:
        result = False
        LOGGER.info('%s: HTTP version not visible on %s:%s, Details=None',
                    show_close(), ip_address, port)
    return result


@track
def is_not_https_required(url):
    """Check if HTTPS is always forced on a given url."""
    assert url.startswith('http://')
    http_session = http_helper.HTTPSession(url)
    if http_session.url.startswith('https'):
        LOGGER.info('%s: HTTPS is forced on URL, Details=%s',
                    show_close(), http_session.url)
        return False
    LOGGER.info('%s: HTTPS is not forced on URL, Details=%s',
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

    max_response_time = 1
    http_session = http_helper.HTTPSession(url, *args, **kwargs)

    response_time = http_session.response.elapsed.total_seconds()
    delta = max_response_time - response_time

    if delta >= 0:
        LOGGER.info('%s: Response time is acceptable for %s, Details=%s',
                    show_close(), http_session.url, str(response_time))
        return False
    LOGGER.info('%s: Response time is not acceptable for %s, Details=%s',
                show_open(), http_session.url, str(response_time))
    return True


@track
def has_user_enumeration(url, user_field, user_list=None, fake_users=None,
                         *args, **kwargs):
    """Check if URL has user enumeration."""

    assert 'params' in kwargs or 'data' in kwargs
    if 'params' in kwargs:
        query_string = kwargs['params']
    elif 'data' in kwargs:
        query_string = kwargs['data']
    assert user_field in query_string

    if not user_list:
        user_list = ['admin', 'administrator', 'guest', 'test']

    if not fake_users:
        fake_users = ['iuaksiuiadbuqywdaskj1234', 'ajahdsjahdjhbaj',
                      'aksjdads@asd.com', 'osvtxodahidhiis@gmail.com',
                      'something@example.com', '12312314511231']

    # Evaluate the response with non-existant users
    datasets = http_helper.create_dataset(user_field, fake_users,
                                          query_string)

    fake_res = list()
    for dataset in datasets:
        if 'data' in kwargs:
            orig_data = kwargs['data']
            kwargs['data'] = dataset
        elif 'params' in kwargs:
            orig_data = kwargs['params']
            kwargs['params'] = dataset
        sess = http_helper.HTTPSession(url, *args, **kwargs)
        fake_res.append((len(sess.response.text),
                         sess.response.status_code))

    if 'data' in kwargs:
        kwargs['data'] = orig_data
    elif 'params' in kwargs:
        kwargs['params'] = orig_data

    datasets = http_helper.create_dataset(user_field, user_list,
                                          query_string)

    user_res = list()
    for dataset in datasets:
        if 'data' in kwargs:
            orig_data = kwargs['data']
            kwargs['data'] = dataset
        elif 'params' in kwargs:
            orig_data = kwargs['params']
            kwargs['params'] = dataset
        sess = http_helper.HTTPSession(url, *args, **kwargs)
        user_res.append((len(sess.response.text),
                         sess.response.status_code))

    num_comp = len(fake_res) * len(user_res)

    merged = []
    for i in fake_res:
        for j in user_res:
            merged.append((i, j))

    from difflib import SequenceMatcher
    res = 0
    for resp_text, resp_time in merged:
        res += SequenceMatcher(None, resp_text, resp_time).ratio()

    rat = round(res / num_comp, 2)

    if rat > 0.95:
        LOGGER.info('%s: User enumeration not possible for %s, \
Details=%s%% of similar answers',
                    show_close(), url, str(rat * 100))
        return False
    LOGGER.info('%s: User enumeration is possible for %s, \
Details=%s%% of similar answers',
                show_open(), url, str(rat * 100))
    return True


@track
def can_brute_force(url, ok_regex, user_field, pass_field, user_list=None,
                    pass_list=None, *args, **kwargs):
    """Check if URL allows brute forcing."""

    assert 'params' in kwargs or 'data' in kwargs
    if 'params' in kwargs:
        query_string = kwargs['params']
    elif 'data' in kwargs:
        query_string = kwargs['data']

    assert isinstance(user_list, list)
    assert isinstance(pass_list, list)

    users_dataset = http_helper.create_dataset(user_field, user_list,
                                               query_string)

    dataset = []
    for password in pass_list:
        for user_ds in users_dataset:
            _datas = http_helper.create_dataset(pass_field, [password], user_ds)
            dataset.append(_datas[0])

    for _datas in dataset:
        if 'params' in kwargs:
            kwargs['params'] = _datas
        elif 'data' in kwargs:
            kwargs['data'] = _datas
        sess = http_helper.HTTPSession(url, *args, **kwargs)
        if ok_regex in sess.response.text:
            LOGGER.info('%s: Brute forcing possible for %s, \
Details=%s params were used', show_open(), url, str(_datas))
            return True
    LOGGER.info('%s: Brute forcing was not successful for %s',
                show_close(), url)
    return False
