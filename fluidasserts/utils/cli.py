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

(_, LOGFILE) = tempfile.mkstemp(suffix='.log')


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


def main():
    """Package CLI."""
    init()
    fluidasserts.show_banner()
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-q', '--quiet', help='decrease output verbosity',
                           action='store_true')
    argparser.add_argument('-c', '--no-color', help='remove colors',
                           action='store_true')
    argparser.add_argument('exploit', help='exploit to execute')

    args = argparser.parse_args()

    my_env = {**os.environ, 'FA_CLI': 'true'}

    with open(LOGFILE, 'w') as outfile:
        ret = call([sys.executable, args.exploit],
                   stdout=outfile, stderr=outfile, env=my_env)

    with open(LOGFILE, 'r') as infile:
        content = infile.read()

    if not args.quiet:
        if args.no_color:
            print(escape_ansi(content))
        else:
            print(content)

    parsed = get_parsed_output(content)

    final_message = {
        'summary': {
            'total-checks': get_total_checks(parsed),
            'opened-checks': get_total_open_checks(parsed),
            'closed-checks': get_total_closed_checks(parsed),
            'unknown-checks': get_total_unknown_checks(parsed)
        }
    }

    print(yaml.dump(final_message, default_flow_style=False,
                    explicit_start=True))

    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            if 'OPEN' in content:
                sys.exit(1)
    return ret
