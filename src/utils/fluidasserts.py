#!/usr/bin/python
#
# FLUIDAsserts launcher

import os
import subprocess
import sys


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print """
        Usage:

        fluidasserts exploit.py
        """
        sys.exit(1)
    cmd = sys.executable + ' ' + sys.argv[1]
    os.system(cmd)
