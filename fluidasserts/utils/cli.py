#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""Asserts CLI."""

# standard imports
import argparse
import os
import sys
import tempfile
from subprocess import call

# pylint: disable=no-name-in-module
# pylint: disable=global-statement

# 3rd party imports
import yaml
from colorama import init
from pygments import highlight
from pygments.lexers import PropertiesLexer
from pygments.formatters import TerminalFormatter
from pygments.token import Keyword, Name, Comment, String, Error, \
    Number, Operator, Generic, Token, Whitespace
from pygments.util import UnclosingTextIOWrapper

# local imports
import fluidasserts


OUTFILE = sys.stdout

OPEN_COLORS = {
    Token: ('', ''),
    Whitespace: ('lightgray', 'darkgray'),
    Comment: ('darkred', 'red'),
    Comment.Preproc: ('darkred', 'red'),
    Keyword: ('darkblue', 'blue'),
    Keyword.Type: ('teal', 'turquoise'),
    Operator.Word: ('purple', 'fuchsia'),
    Name.Builtin: ('teal', 'turquoise'),
    Name.Function: ('darkgreen', 'green'),
    Name.Namespace: ('_teal_', '_turquoise_'),
    Name.Class: ('_darkgreen_', '_green_'),
    Name.Exception: ('teal', 'turquoise'),
    Name.Decorator: ('darkgray', 'lightgray'),
    Name.Variable: ('darkred', 'red'),
    Name.Constant: ('darkred', 'red'),
    Name.Attribute: ('lightgray', 'darkgray'),
    Name.Tag: ('blue', 'blue'),
    String: ('red', 'red'),
    Number: ('red', 'red'),
    Generic.Deleted: ('red', 'red'),
    Generic.Inserted: ('darkgreen', 'green'),
    Generic.Heading: ('**', '**'),
    Generic.Subheading: ('*purple*', '*fuchsia*'),
    Generic.Prompt: ('**', '**'),
    Generic.Error: ('red', 'red'),
    Error: ('red', 'red'),
}

CLOSE_COLORS = {
    Token: ('', ''),
    Whitespace: ('lightgray', 'darkgray'),
    Comment: ('lightgray', 'darkgray'),
    Comment.Preproc: ('teal', 'turquoise'),
    Keyword: ('darkblue', 'blue'),
    Keyword.Type: ('teal', 'turquoise'),
    Operator.Word: ('purple', 'fuchsia'),
    Name.Builtin: ('teal', 'turquoise'),
    Name.Function: ('darkgreen', 'green'),
    Name.Namespace: ('_teal_', '_turquoise_'),
    Name.Class: ('_darkgreen_', '_green_'),
    Name.Exception: ('teal', 'turquoise'),
    Name.Decorator: ('darkgray', 'lightgray'),
    Name.Variable: ('darkred', 'red'),
    Name.Constant: ('darkred', 'red'),
    Name.Attribute: ('lightgray', 'darkgray'),
    Name.Tag: ('blue', 'blue'),
    String: ('*darkgreen*', '*green*'),
    Number: ('*darkgreen*', '*green*'),
    Generic.Deleted: ('red', 'red'),
    Generic.Inserted: ('darkgreen', 'green'),
    Generic.Heading: ('**', '**'),
    Generic.Subheading: ('*purple*', '*fuchsia*'),
    Generic.Prompt: ('**', '**'),
    Generic.Error: ('red', 'red'),
    Error: ('*darkgreen*', '*green*'),
}

UNKNOWN_COLORS = {
    Token: ('', ''),
    Whitespace: ('lightgray', 'darkgray'),
    Comment: ('lightgray', 'darkgray'),
    Comment.Preproc: ('teal', 'turquoise'),
    Keyword: ('darkblue', 'blue'),
    Keyword.Type: ('teal', 'turquoise'),
    Operator.Word: ('purple', 'fuchsia'),
    Name.Builtin: ('teal', 'turquoise'),
    Name.Function: ('darkgreen', 'green'),
    Name.Namespace: ('_teal_', '_turquoise_'),
    Name.Class: ('_darkgreen_', '_green_'),
    Name.Exception: ('teal', 'turquoise'),
    Name.Decorator: ('darkgray', 'lightgray'),
    Name.Variable: ('darkred', 'red'),
    Name.Constant: ('darkred', 'red'),
    Name.Attribute: ('lightgray', 'darkgray'),
    Name.Tag: ('blue', 'blue'),
    String: ('*teal*', '*teal*'),
    Number: ('*teal*', '*teal*'),
    Generic.Deleted: ('red', 'red'),
    Generic.Inserted: ('darkgreen', 'green'),
    Generic.Heading: ('**', '**'),
    Generic.Subheading: ('*purple*', '*fuchsia*'),
    Generic.Prompt: ('**', '**'),
    Generic.Error: ('red', 'red'),
    Error: ('*teal*', '*teal*'),
}

SUMMARY_COLORS = {
    Token: ('', ''),
    Whitespace: ('lightgray', 'darkgray'),
    Comment: ('lightgray', 'darkgray'),
    Comment.Preproc: ('teal', 'turquoise'),
    Keyword: ('darkblue', 'blue'),
    Keyword.Type: ('teal', 'turquoise'),
    Operator.Word: ('purple', 'fuchsia'),
    Name.Builtin: ('teal', 'turquoise'),
    Name.Function: ('darkgreen', 'green'),
    Name.Namespace: ('_teal_', '_turquoise_'),
    Name.Class: ('_darkgreen_', '_green_'),
    Name.Exception: ('teal', 'turquoise'),
    Name.Decorator: ('white', 'lightgray'),
    Name.Variable: ('darkred', 'red'),
    Name.Constant: ('darkred', 'red'),
    Name.Attribute: ('lightgray', 'white'),
    Name.Tag: ('blue', 'blue'),
    String: ('white', 'white'),
    Number: ('white', 'white'),
    Generic.Deleted: ('red', 'red'),
    Generic.Inserted: ('darkgreen', 'green'),
    Generic.Heading: ('**', '**'),
    Generic.Subheading: ('*purple*', '*fuchsia*'),
    Generic.Prompt: ('**', '**'),
    Generic.Error: ('red', 'red'),
    Error: ('white', 'white'),
}


def enable_win_colors():
    """Enable windows colors."""
    global OUTFILE
    if sys.platform in ('win32', 'cygwin'):  # pragma: no cover
        OUTFILE = UnclosingTextIOWrapper(sys.stdout.buffer)
        try:
            import colorama.initialise
        except ImportError:
            pass
        else:
            OUTFILE = colorama.initialise.wrap_stream(OUTFILE, convert=None,
                                                      strip=None,
                                                      autoreset=False,
                                                      wrap=True)


def show_banner():
    """Show Asserts banner."""
    enable_win_colors()
    header = """
---
# Fluid Asserts (v. {})
#  ___
# | >>|> fluid
# |___|  attacks, we hack your software
#
# Loading attack modules ...
""".format(fluidasserts.__version__)

    highlight(header, PropertiesLexer(),
              TerminalFormatter(colorscheme=OPEN_COLORS), OUTFILE)


def get_parsed_output(content):
    """Get parsed YAML output."""
    try:
        ret = [x for x in yaml.safe_load_all(content)]
    except yaml.scanner.ScannerError:  # pragma: no cover
        print(content, flush=True)
        sys.exit(-1)
    else:
        return ret


def get_total_checks(output_list):
    """Get total checks."""
    return len(output_list)


def get_total_open_checks(output_list):
    """Get total open checks."""
    return sum(output['status'] == 'OPEN' for output in output_list)


def get_total_closed_checks(output_list):
    """Get total closed checks."""
    return sum(output['status'] == 'CLOSED' for output in output_list)


def get_total_unknown_checks(output_list):
    """Get total unknown checks."""
    return sum(output['status'] == 'UNKNOWN' for output in output_list)


def filter_content(parsed_content, args):
    """Show filtered content according to args."""
    opened_nodes = filter(lambda x: x['status'] == 'OPEN' and args.show_open,
                          parsed_content)
    closed_nodes = filter(lambda x: x['status'] == 'CLOSED' and
                          args.show_closed,
                          parsed_content)
    unknown_nodes = filter(lambda x: x['status'] == 'UNKNOWN' and
                           args.show_unknown,
                           parsed_content)

    return list(opened_nodes) + list(closed_nodes) + list(unknown_nodes)


def get_risk_levels(parsed_content):
    """Get risk levels of opened checks."""
    try:
        high_risk = sum(x['status'] == 'OPEN' and
                        x['risk-level'] == 'high' for x in parsed_content)
        medium_risk = sum(x['status'] == 'OPEN' and
                          x['risk-level'] == 'medium' for x in parsed_content)
        low_risk = sum(x['status'] == 'OPEN' and
                       x['risk-level'] == 'low' for x in parsed_content)

        opened = get_total_open_checks(parsed_content)

        if opened > 0:
            risk_level = {
                'high': '{} ({:.2f}%)'.format(high_risk,
                                              high_risk / opened * 100),
                'medium': '{} ({:.2f}%)'.format(medium_risk,
                                                medium_risk / opened * 100),
                'low': '{} ({:.2f}%)'.format(low_risk,
                                             low_risk / opened * 100),
            }
        else:
            risk_level = {
                'high': '0 (0%)',
                'medium': '0 (0%)',
                'low': '0 (0%)',
            }
    except KeyError:
        risk_level = 'undefined'
    return risk_level


def colorize(parsed_content):
    """Colorize content."""
    enable_win_colors()
    for node in parsed_content:
        if node['status'] == 'OPEN':
            style = OPEN_COLORS
        elif node['status'] == 'CLOSED':
            style = CLOSE_COLORS
        elif node['status'] == 'UNKNOWN':
            style = UNKNOWN_COLORS
        else:
            style = SUMMARY_COLORS

        message = yaml.safe_dump(node, default_flow_style=False,
                                 explicit_start=True)
        highlight(message, PropertiesLexer(),
                  TerminalFormatter(colorscheme=style),
                  OUTFILE)


def print_message(message, args):
    """Print message according to args."""
    if args.no_color:
        print(yaml.safe_dump(message, default_flow_style=False,
                             explicit_start=True), flush=True)
    else:
        colorize(message)


def exec_wrapper(exploit):
    """Execute exploit wrapper."""
    (_, logfile) = tempfile.mkstemp(suffix='.log')

    my_env = {**os.environ, 'FA_CLI': 'true'}

    with open(logfile, 'w') as outfile:
        ret = call([sys.executable, exploit],
                   stdout=outfile, stderr=outfile, env=my_env)

    with open(logfile, 'r') as infile:
        content = infile.read()

    if os.path.exists(logfile):
        try:
            os.remove(logfile)
        except PermissionError:
            pass

    return (ret, content)


def exec_http_package(urls):
    """Execute generic checks of HTTP package."""
    template = """
from fluidasserts.proto import http
"""
    for url in urls:
        template += """
http.is_header_x_asp_net_version_present('__url__')
http.is_header_access_control_allow_origin_missing('__url__')
http.is_header_cache_control_missing('__url__')
http.is_header_content_security_policy_missing('__url__')
http.is_header_content_type_missing('__url__')
http.is_header_expires_missing('__url__')
http.is_header_pragma_missing('__url__')
http.is_header_server_present('__url__')
http.is_header_x_content_type_options_missing('__url__')
http.is_header_x_frame_options_missing('__url__')
http.is_header_perm_cross_dom_pol_missing('__url__')
http.is_header_x_xxs_protection_missing('__url__')
http.is_header_hsts_missing('__url__')
http.is_basic_auth_enabled('__url__')
http.has_trace_method('__url__')
http.has_delete_method('__url__')
http.has_put_method('__url__')
http.is_sessionid_exposed('__url__')
http.is_version_visible('__url__')
http.has_dirlisting('__url__')
http.has_clear_viewstate('__url__')
http.is_response_delayed('__url__')
http.has_clear_viewstate('__url__')
http.is_date_unsyncd('__url__')

""".replace('__url__', url)

    (_, exploitfile) = tempfile.mkstemp(suffix='.py')
    with open(exploitfile, 'w+') as exploitfd:
        exploitfd.write(template)

    return exec_wrapper(exploitfile)


def exec_ssl_package(ip_addresses):
    """Execute generic checks of SSL package."""
    template = """
from fluidasserts.proto import ssl
from fluidasserts.format import x509
"""
    for ip_addr in ip_addresses:
        template += """
ssl.is_pfs_disabled('__ip__')
ssl.is_sslv3_enabled('__ip__')
ssl.is_tlsv1_enabled('__ip__')
ssl.has_poodle_tls('__ip__')
ssl.has_poodle_sslv3('__ip__')
ssl.has_breach('__ip__')
ssl.allows_anon_ciphers('__ip__')
ssl.allows_weak_ciphers('__ip__')
ssl.has_beast('__ip__')
ssl.has_heartbleed('__ip__')
ssl.allows_modified_mac('__ip__')
x509.is_cert_cn_not_equal_to_site('__ip__')
x509.is_cert_inactive('__ip__')
x509.is_cert_validity_lifespan_unsafe('__ip__')
x509.is_sha1_used('__ip__')
x509.is_md5_used('__ip__')
""".replace('__ip__', ip_addr)

    (_, exploitfile) = tempfile.mkstemp(suffix='.py')
    with open(exploitfile, 'w+') as exploitfd:
        exploitfd.write(template)

    return exec_wrapper(exploitfile)


def exec_dns_package(nameservers):
    """Execute generic checks of DNS package."""
    template = """
from fluidasserts.proto import dns
"""
    for nameserver in nameservers:
        template += """
dns.has_cache_snooping('__ip__')
dns.has_recursion('__ip__')
dns.can_amplify('__ip__')
""".replace('__ip__', nameserver)

    (_, exploitfile) = tempfile.mkstemp(suffix='.py')
    with open(exploitfile, 'w+') as exploitfd:
        exploitfd.write(template)

    return exec_wrapper(exploitfile)


def get_content(args):
    """Get raw content according to args parameter."""
    content = ''
    if args.http:
        (ret, _content) = exec_http_package(args.http)
        content += _content
    if args.ssl:
        (ret, _content) = exec_ssl_package(args.ssl)
        content += _content
    if args.dns:
        (ret, _content) = exec_dns_package(args.dns)
        content += _content
    elif args.exploit:
        (ret, _content) = exec_wrapper(args.exploit)
        content += _content
    return (ret, content)


def main():
    """Run CLI."""
    init()
    show_banner()
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-q', '--quiet', help='decrease output verbosity',
                           action='store_true')
    argparser.add_argument('-n', '--no-color', help='remove colors',
                           action='store_true')
    argparser.add_argument('-o', '--show-open', help='show only opened checks',
                           action='store_true')
    argparser.add_argument('-c', '--show-closed',
                           help='show only closed checks',
                           action='store_true')
    argparser.add_argument('-u', '--show-unknown',
                           help='show only unknown (error) checks',
                           action='store_true')
    argparser.add_argument('-H', '--http', nargs='+', metavar='URL',
                           help='perform generic HTTP checks over given URL')
    argparser.add_argument('-S', '--ssl', nargs='+', metavar='IP',
                           help='perform generic SSL checks over given IP')
    argparser.add_argument('-D', '--dns', nargs='+', metavar='NS',
                           help='perform generic DNS checks \
over given nameserver')
    argparser.add_argument('exploit', nargs='?', help='exploit to execute')

    args = argparser.parse_args()

    if not args.exploit and not args.http and not args.ssl and not args.dns:
        argparser.print_help()
        sys.exit(-1)

    (ret, content) = get_content(args)

    parsed = get_parsed_output(content)

    if not args.quiet:
        if args.show_open or args.show_closed or args.show_unknown:
            print_message(filter_content(parsed, args), args)
        else:
            print_message(parsed, args)

    total_checks = get_total_checks(parsed)
    open_checks = get_total_open_checks(parsed)
    closed_checks = get_total_closed_checks(parsed)
    unknown_checks = get_total_unknown_checks(parsed)

    final_message = {
        'summary': {
            'checks': {
                'total': '{} ({}%)'.format(total_checks, '100'),
                'unknown':
                    '{} ({:.2f}%)'.format(unknown_checks,
                                          unknown_checks / total_checks * 100),
                'closed':
                    '{} ({:.2f}%)'.format(closed_checks,
                                          closed_checks / total_checks * 100),
                'opened':
                    '{} ({:.2f}%)'.format(open_checks,
                                          open_checks / total_checks * 100),
            },
            'risk': get_risk_levels(parsed),
        }
    }

    message = yaml.safe_dump(final_message, default_flow_style=False,
                             explicit_start=True)

    highlight(message, PropertiesLexer(),
              TerminalFormatter(colorscheme=SUMMARY_COLORS), OUTFILE)

    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            if 'OPEN' in content:
                sys.exit(1)
    return ret
