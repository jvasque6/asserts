#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""Asserts CLI."""

# standard imports
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


def get_parsed_output():
    """Get parsed YAML output."""
    output_list = []
    with open(LOGFILE) as fd_yaml:
        parsed = yaml.load_all(escape_ansi(fd_yaml.read()))
    for output in parsed:
        output_list.append(output)
    return output_list


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
    if len(sys.argv) < 2:
        fluidasserts.show_banner()
        sys.stderr.write('Usage: asserts <exploit.py>\n')
        return 1
    my_env = {**os.environ, 'FA_CLI': 'true'}
    fluidasserts.show_banner()
    with open(LOGFILE, 'w') as outfile:
        ret = call([sys.executable, sys.argv[1]],
                   stdout=outfile, stderr=outfile, env=my_env)
    with open(LOGFILE, 'r') as infile:
        content = infile.read()
    print(content)
    parsed = get_parsed_output()

    final_message = {
        'Total checks': get_total_checks(parsed),
        'Opened checks': get_total_open_checks(parsed),
        'Closed checks': get_total_closed_checks(parsed),
        'Unknown checks': get_total_unknown_checks(parsed)
    }

    print(yaml.dump(final_message, default_flow_style=False,
                    explicit_start=True))

    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            if 'OPEN' in content:
                sys.exit(1)
    return ret
