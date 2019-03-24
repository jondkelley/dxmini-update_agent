#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""Demo Module

Usage:
    dxmini ping --hello

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

from pathlib import Path
import json
import time, os, stat
import subprocess
import miniupnpc
import uuid
# protips
# yorktown demo --example [-s STRING, -n TIMES] = either option
# yorktown demo --example [-s STRING | -n TIMES] = one or the other
# changing [] to () makes optional parameters required
import socket
import requests
import time
import random
from docopt import docopt
from dxmini.lib.utils import get_arg_option
from dxmini.lib.utils import print_arguements
import subprocess
import sys
import os
import logging
logger = logging.getLogger(__name__)
import psutil
import time

PRODUCT_NAME = "dxmini"

def uptime():
    """
    return raspi uptime
    """
    return time.time() - psutil.boot_time()

def get_support_id():
    """
    returns support id from flash
    generates a support id if it's missing
    """
    serialfile = '/etc/dxmini_serial'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial
    else:
        serial = "".join(str(uuid.uuid4()).split('-')[3:]).upper()
        serial = str(int(serial, 16))
        with open(serialfile,"w") as fi:
            fi.write(serial)
            fi.close()
        return serial

def get_model():
    """
    returns model from flash
    """
    serialfile = '/etc/dxmini_model'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial
    else:
        return "unknown_model"

def get_revision():
    """
    returns revision from flash
    """
    serialfile = '/etc/dxmini_revision'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial
    else:
        return "unknown_revision"

def get_current_call():
    """
    get current call
    """
    return "unknown"

def get_first_call():
    """
    returns first call used in flash
    """
    serialfile = '/etc/first_user'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial
    else:
        return "nobody"

def get_warranty_activation_date():
    """
    returns activation date from flash for warranty tracking
    """
    serialfile = '/.activation'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial
    else:
        return "unknown_revision"

def file_age_in_seconds(pathname):
    """
    return a files exact age in seconds
    """
    return time.time() - os.stat(pathname)[stat.ST_MTIME]

def selfie():
    """
    cache local and remote interface
    """
    if os.path.isfile('/tmp/.0'):
        if file_age_in_seconds > 43200:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # doesn't even have to be reachable, neat trick eh?
                s.connect(('10.255.255.255', 1))
                a = s.getsockname()[0]
            except:
                a = '127.0.0.1'
            finally:
                s.close()

            with open('/tmp/.0',"w") as fi:
                fi.write(a)
        else:
            with open("/tmp/.0", "r") as fcontext:
                a = fcontext.read()

    if os.path.isfile('/tmp/.1'):
        if file_age_in_seconds > 43200:
            try:
                r = requests.get('http://ifconfig.me')
                b = r.text
            except:
                try:
                    r = requests.get('http://api.dxmini.uberleet.org/dxmini-function/selfie')
                    b = r.text
                except:
                    b = '169.169.169.255'

            with open('/tmp/.1',"w") as fi:
                fi.write(b)
        else:
            with open("/tmp/.1", "r") as fcontext:
                b = fcontext.read()
    return (a, b)

def announce_client():
    struct = {
        "firstcall": get_first_call(),
        "curcall": get_current_call(),
        "support_id": get_support_id(),
        "rev": get_revision(),
        "model": get_model(),
        "start_warranty": get_warranty_activation_date(),
        ##"in": selfie()[0],
        ##"out": selfie()[1],
        "uptime": int(uptime())
    }
    print(struct)
    try:
        manifest_url = "https://raw.githubusercontent.com/jondkelley/dxmini-releasemap/master/manifest.json"
        manifest = requests.get(manifest_url)
        client_registration_url_prefix = manifest.json()['client_announce_prefix']
        client_registration_url = "{prefix}/v1.0/registration"
        announce = requests.post(client_registration_url, data=json.dumps(struct))
    except:
        print("Error sending hello")

logger = logging.getLogger(__name__)

FILE_PREFIX = "."

if os.path.isfile('{}/dxmini_serial'.format(FILE_PREFIX)):
    pass#exit(0)

def serial_generator():
    return str(int("".join(str(uuid.uuid4()).split('-')[:3]), 16))

class pingCommand():
    """dxmini provision
    Argument:
        args (dict): A dictionary returned by docopt afte CLI is parsed
    """
    def __init__(self, args):
        self.args = args
        print_arguements(args)

    def hello(self):
        """
        pinghello
        """
        print("Sending hello")
        ## Generate serial number
        announce_client()

def main():
    """Parse the CLI"""
    arguments = docopt(__doc__)

    cmd = pingCommand(arguments)
    method = get_arg_option(arguments)
    getattr(cmd, method)()

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
