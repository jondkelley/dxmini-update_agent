#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""Demo Module

Usage:
    dxmini provision --helloworld [-s STRING, -n TIMES, -b BOOL]
    dxmini provision --setup
    dxmini provision -h

Arguments:
    STRING     Change demo string output
    TIMES      Repeat string demo number of times
    BOOL       Boolean value
    CMD        A specific command to run in subprocess

Options:
    -h                          show this message
    --helloworld                run demo
    -b BOOL, --boolean BOOL     print something if boolean set
                                [default: false]
    -s STRING, --string STRING  string to show
                                [default: hello world]
    -n TIMES, --number TIMES    number of times to repeat STRING
                                [default: 1]
    -c CMD                      command to run
                                [default: ps]
"""
# protips
# dxmini demo --example [-s STRING, -n TIMES] = either option
# dxmini demo --example [-s STRING | -n TIMES] = one or the other
# changing [] to () makes optional parameters required

from docopt import docopt
from dxmini.lib.utils import get_arg_option
from dxmini.lib.utils import print_arguements
from dxmini.lib.utils import AnsiColor as color
from dxmini import DXMINI_MANIFEST_URL
import subprocess
import sys
import os
import logging
import requests
import json
from subprocess import Popen, PIPE
from os import environ
import hashlib
import tarfile
import uuid
import json, codecs
from pathlib import Path

logger = logging.getLogger(__name__)

FILE_PREFIX = "/etc"

def serial_generator():
    return str(int("".join(str(uuid.uuid4()).split('-')[:3]), 16))

def touch(path):
    with open(path, 'a'):
        os.utime(path, None)

class provisionCommand():
    """dxmini provision
    Argument:
        args (dict): A dictionary returned by docopt afte CLI is parsed
    """
    def __init__(self, args):
        self.args = args
        print_arguements(args)

    def setup(self):
        """
        provision first time users
        """
        # Activate device
        touch('/.activate')

        ## Generate serial number
        with open('{}/dxmini_serial'.format(FILE_PREFIX), 'w') as f:
            #json.dump(data, codecs.getwriter('utf-8')(f), ensure_ascii=False)
            f.write(serial_generator())

def main():
    """Parse the CLI"""
    arguments = docopt(__doc__)

    cmd = provisionCommand(arguments)
    method = get_arg_option(arguments)
    getattr(cmd, method)()

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
