#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""Asserts CLI."""

# standard imports
import argparse
import os
import re
import sys
import tempfile
from subprocess import call

# 3rd party imports
from colorama import init
import yaml

# local imports
import fluidasserts


def escape_ansi(line):
    """Remove ANSI chars from string."""
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)


def get_parsed_output(content):
    """Get parsed YAML output."""
    return [x for x in yaml.load_all(escape_ansi(content))]


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


def exec_wrapper(exploit):
    """Wrapper executor exploit."""
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
            print('Could not remove temp file {}. \
Consider removing it manually'.format(logfile))

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
http.is_resource_accessible('__url__')
http.is_response_delayed('__url__')
http.has_clear_viewstate('__url__')
http.is_date_unsyncd('__url__')

""".replace('__url__', url)

    (_, exploitfile) = tempfile.mkstemp(suffix='.py')
    with open(exploitfile, 'w+') as exploitfd:
        exploitfd.write(template)

    return exec_wrapper(exploitfile)


def main():
    """Package CLI."""
    init()
    fluidasserts.show_banner()
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
    argparser.add_argument('exploit', nargs='?', help='exploit to execute')

    args = argparser.parse_args()

    if not args.exploit and not args.http:
        argparser.print_help()
        sys.exit(-1)

    if args.http:
        (ret, content) = exec_http_package(args.http)
    elif args.exploit:
        (ret, content) = exec_wrapper(args.exploit)

    parsed = get_parsed_output(content)

    if not args.quiet:
        if args.show_open or args.show_closed or args.show_unknown:
            print(yaml.dump(filter_content(parsed, args),
                            default_flow_style=False,
                            explicit_start=True))
        else:
            if args.no_color:
                print(escape_ansi(content))
            else:
                print(content)

    total_checks = get_total_checks(parsed)
    open_checks = get_total_open_checks(parsed)
    closed_checks = get_total_closed_checks(parsed)
    unknown_checks = get_total_unknown_checks(parsed)

    final_message = {
        'summary': {
            'total-checks': '{} ({}%)'.format(total_checks, '100'),
            'opened-checks':
                '{} ({:.2f}%)'.format(open_checks,
                                      open_checks / total_checks * 100),
            'closed-checks':
                '{} ({:.2f}%)'.format(closed_checks,
                                      closed_checks / total_checks * 100),
            'unknown-checks':
                '{} ({:.2f}%)'.format(unknown_checks,
                                      unknown_checks / total_checks * 100),
        }
    }

    print(yaml.dump(final_message, default_flow_style=False,
                    explicit_start=True))

    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            if 'OPEN' in content:
                sys.exit(1)
    return ret
