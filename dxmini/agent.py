#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""Demo Module

Usage:
    dxmini agent --helloworld [-s STRING, -n TIMES, -b BOOL]
    dxmini agent --update
    dxmini agent -h

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

logger = logging.getLogger(__name__)

def md5(fname):
    """
    calculate md5sum for files
    """
    hash_md5 = hashlib.md5()
    try:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return False

def download_file(url, filename):
    """
    chunk download so we can support very large files
    """
    response = requests.get(url, stream=True)

    # Throw an error for bad status codes
    response.raise_for_status()

    with open(filename, 'wb') as handle:
        for block in response.iter_content(1024):
            handle.write(block)

def update_dashboard(manifest):
    """
    update the dashboard code
    """

    ##########
    # Download
    dashboard_filename = 'dashboard.tar.gz'

    latest_tag = manifest['latest_version']
    latest_tarball = manifest['version_map'][latest_tag]['url']
    latest_tarball_md5 = manifest['version_map'][latest_tag]['md5']
    if md5(dashboard_filename) == latest_tarball_md5:
        logger.info("Your dxmini dashboard is already the latest version!")
    else:
        os.unlink(dashboard_filename)
        logger.info("Downloading {}".format(latest_tarball))
        download_file(latest_tarball, dashboard_filename)

    #########
    # Update!
    tf = tarfile.open(dashboard_filename)
    tf.extractall("./htdocs")

def update_updater(manifest):
    """
    update the update script
    """
    updater_filename = "dxmini-update"

    ##########
    # Download
    latest_script = manifest['latest_script']
    latest_script_md5 = manifest['latest_script_md5']
    if md5(updater_filename) == latest_script_md5:
        logger.info("Your update script is already the latest version!")
    else:
        os.unlink(updater_filename)
        logger.info("Downloading {}".format(latest_script))
        download_file(latest_script, updater_filename)

    #########
    # Update!

class AgentCommand():
    """dxmini agent
    Argument:
        args (dict): A dictionary returned by docopt afte CLI is parsed
    """
    def __init__(self, args):
        self.args = args
        print_arguements(args)

    def update(self):
        """
        update dxmini
        """

        r = requests.get(DXMINI_MANIFEST_URL)
        manifest = r.json()
        if manifest['_self_federated']:
            r = requests.get(manifest['_self'])
            manifest = r.json()
        else:
            logger.debug("No federated manifest, using defaults...")

        print(json.dumps(manifest, indent=3))

        update_updater(manifest)
        update_dashboard(manifest)

    def helloworld(self):
        """
        hello world example
        """
        string = self.args['--string']
        count = int(self.args['--number'])
        for i in range(count):
            print(string)
        if self.args['--boolean'].lower().startswith("t"):
            print("something")

    def cmd(self):
        """
        arbitrary command example
        """
        cmd = self.args['-c']
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (stdout, stderr) = p.communicate()
        exit_code = p.wait()
        print("EXEC:\n   {}".format(cmd))
        print("STDOUT:")
        for line in stdout.split("\n"):
            print("   {}".format(line))
        exit(exit_code)

def main():
    """Parse the CLI"""
    arguments = docopt(__doc__)

    cmd = AgentCommand(arguments)
    method = get_arg_option(arguments)
    getattr(cmd, method)()

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
