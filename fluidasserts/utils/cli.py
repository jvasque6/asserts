#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""Asserts CLI."""

# standard imports
import os
import sys
import tempfile
from subprocess import call

# 3rd party imports
from colorama import init

# local imports
import fluidasserts

(_, LOGFILE) = tempfile.mkstemp(suffix='.log')


def main():
    """Package CLI."""
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: asserts <exploit.py>\n')
        return 1
    init()
    my_env = {**os.environ, 'FA_CLI': 'true'}
    fluidasserts.show_banner()
    with open(LOGFILE, 'w') as outfile:
        ret = call([sys.executable, sys.argv[1]],
                   stdout=outfile, stderr=outfile, env=my_env)
    with open(LOGFILE, 'r') as infile:
        content = infile.read()
    print(content)

    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            if 'OPEN' in content:
                sys.exit(1)
    return ret
