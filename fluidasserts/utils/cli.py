#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""Asserts CLI."""

# standard imports
import os
import sys
from subprocess import call

# 3rd party imports
# None

# local imports
import fluidasserts

LOGFILE = '/tmp/fluidasserts.log'


def main():
    """Package CLI."""
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: asserts <exploit.py>\n')
        return 1
    fluidasserts.show_banner()
    with open(LOGFILE, 'w') as outfile:
        ret = call([sys.executable, sys.argv[1]],
                   stdout=outfile, stderr=outfile)
    with open(LOGFILE, 'r') as infile:
        content = infile.read()
    print(content)

    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            if 'OPEN' in content:
                sys.exit(1)
    return ret
