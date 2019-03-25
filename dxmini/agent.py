#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""Demo Module

Usage:
    dxmini agent --ping
    dxmini agent --update
    dxmini agent --provision
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

from collections import defaultdict
import configparser
import shutil
import subprocess
from distutils.version import StrictVersion
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
import time
import psutil
import uuid
import platform

logger = logging.getLogger(__name__)


################################
# Initial provisioning and stuff
################################

def serial_generator():
    return str(int("".join(str(uuid.uuid4()).split('-')[:3]), 16))

def touch(path):
    with open(path, 'a'):
        os.utime(path, None)

##########################
# ping functions and stuff
##########################
def creation_date(path_to_file):
    """
    Try to get the date that a file was created, falling back to when it was
    last modified if that isn't possible.
    See http://stackoverflow.com/a/39501288/1709587 for explanation.
    """
    if platform.system() == 'Windows':
        return os.path.getctime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            return stat.st_birthtime
        except AttributeError:
            # We're probably on Linux. No easy way to get creation dates here,
            # so we'll settle for when its content was last modified.
            return stat.st_mtime

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

def get_upnp_settings():
    """
    retrieves current upnp configurations
    """
    upnp_enabled_cmd = """grep '$DAEMON -a' /usr/local/sbin/pistar-upnp.service  | grep -e '^#' | awk '{ print "inside", $5 , "outside", $6, $7}'"""
    upnp_disabled_cmd = """grep '$DAEMON -a' /usr/local/sbin/pistar-upnp.service  | grep -v -e '^#' | awk '{ print "inside", $5 , "outside", $5, $6}'"""
    if os.path.isfile('/usr/local/sbin/pistar-upnp.service'):
        p = subprocess.Popen(upnp_enabled_cmd, stdout=subprocess.PIPE, shell=True)
        (enabled_upnp, err) = p.communicate()
        p = subprocess.Popen(upnp_disabled_cmd, stdout=subprocess.PIPE, shell=True)
        (disabled_upnp, err) = p.communicate()
        return {
            "enabled": str(enabled_upnp),
            "disabled": str(disabled_upnp)
            }
    else:
        return False

def get_wpa_supplicant():
    """
    retrieves wifi configs without passwords of course
    """
    if os.path.isfile('/etc/wpa_supplicant/wpa_supplicant.conf'):
        supplicant_cmd = """cat /etc/wpa_supplicant/wpa_supplicant.conf | sed -e 's/.*psk.*/\tpsk=\"***\"/'"""
        p = subprocess.Popen(supplicant_cmd, stdout=subprocess.PIPE, shell=True)
        (supplicant, err) = p.communicate()
        return str(supplicant)
    else:
        return False

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
        return None

def get_timezone():
    """return tzinfo"""
    myfile = '/etc/timezone'
    if os.path.isfile(myfile):
        with open(myfile,"r") as fi:
            tz = fi.read()
            return tz
    else:
        return None

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
        return None

def get_historical_calls():
    """
    get current call
    """
    histuser_file = '/etc/.callsign_history'
    if not os.path.isfile(histuser_file):
        logger.info("Need to build")
        history = {"first_call": get_current_call(), "callsign_history": [get_current_call()]}
        with open(histuser_file,"w") as fi:
            logger.info("Build new index")
            fi.write(json.dumps(history, indent=3))
            return history
    else:
        with open(histuser_file,"r") as fi:
            history = json.loads(fi.read())
            if get_current_call() not in history['callsign_history']:
                logger.info("Adding new index")
                history['callsign_history'].append(get_current_call())
                with open(histuser_file,"w") as fi:
                    logger.info("Build new index")
                    fi.write(json.dumps(history, indent=3))
                    return history
            else:
                logger.info("Returning existing index")
                return history
            return first_user

def get_historical_rids():
    """
    get historical radio ids
    """
    histuser_file = '/etc/.rid_history'
    if not os.path.isfile(histuser_file):
        logger.info("Need to build")
        history = {"first_rid": get_current_rid(), "rid_history": [get_current_rid()]}
        with open(histuser_file,"w") as fi:
            logger.info("Build new index")
            fi.write(json.dumps(history, indent=3))
            return history
    else:
        with open(histuser_file,"r") as fi:
            history = json.loads(fi.read())
            if get_current_rid() not in history['rid_history']:
                logger.info("Adding new index")
                history['rid_history'].append(get_current_rid())
                with open(histuser_file,"w") as fi:
                    logger.info("Build new index")
                    fi.write(json.dumps(history, indent=3))
                    return history
            else:
                logger.info("Returning existing index")
                return history
            return first_user

def get_current_call():
    """
    returns first call used in flash
    """
    firstuser_file = '/etc/first_user'
    # try:
    #     with open(firstuser_file,"r") as fi:
    #         first_user = fi.read()
    #         return first_user
    # except:
    #     pass

    config = get_mmdvm_config()
    first_user = config['mmdvm_general'].get('callsign', None)
    if first_user:
        with open(firstuser_file,"w") as fi:
            fi.write(first_user)
    else:
        return "ABCDEFG"
    return first_user

def get_current_rid():
    """
    returns current radio id
    """
    firstuser_file = '/etc/first_rid'
    # try:
    #     with open(firstuser_file,"r") as fi:
    #         first_user = fi.read()
    #         return first_user
    # except:
    #     pass

    config = get_mmdvm_config()
    first_user = config['mmdvm_general'].get('id', None)
    if first_user:
        with open(firstuser_file,"w") as fi:
            fi.write(first_user)
    else:
        return "0"
    return first_user

def get_warranty_activation_date():
    """
    returns activation date from flash for warranty tracking
    """
    serialfile = '/.activate'
    if os.path.isfile(serialfile):
        return int(creation_date('/.activate'))
    else:
        return None

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
    historical_calls = get_historical_calls()
    historical_rids = get_historical_rids()
    hello = {
        "identity": {
            "callsigns": {
                "after_purchase":  historical_calls['first_call'],
                "historical": historical_calls['callsign_history'],
                "current": get_current_call(),
            },
            "dmr": {
                "after_purchase":  historical_rids['first_rid'],
                "historical": historical_rids['rid_history'],
                "current": get_current_rid(),
            }
        },
        "device": {
            "service_tag": get_support_id().rstrip(),
            "rev": get_revision(),
            "model": get_model(),
            "start_warranty": get_warranty_activation_date(),
            "device_uptime": int(uptime()),
            "tz": get_timezone()
        },
        "config": {
            "settings": get_mmdvm_config(),
            "wpa_supplicant": str(get_wpa_supplicant()),
            "upnp": get_upnp_settings()
        }
    }
    print(
        json.dumps(hello, indent=3)
        )
    try:
        manifest_url = "https://raw.githubusercontent.com/jondkelley/dxmini-releasemap/master/manifest.json"
        manifest = requests.get(manifest_url)
        client_registration_url_prefix = manifest.json()['client_announce_prefix']
        client_registration_url = "{prefix}/v1.0/registration"
        announce = requests.post(client_registration_url, data=json.dumps(hello))
    except:
        logger.error("Registration server is offline")

def get_mmdvm_config():
    """
    retrieve some settings from the mmdvm if available
    """
    distilled_config = {}
    #############################
    config = configparser.ConfigParser()
    config.read('/etc/mmdvmhost')
    try:
        distilled_config['mmdvm_general'] = config._sections['General']
    except:
        distilled_config['mmdvm_general'] = {}

    try:
        distilled_config['mmdvm_info'] = config._sections['Info']
    except:
        distilled_config['mmdvm_info'] = {}

    try:
        distilled_config['network_summary'] = {
            "dmr" : config.get('DMR', 'Enable'),
            "dmr_net" : config.get('DMR Network', 'Enable'),
            "nxdn" : config.get('NXDN', 'Enable'),
            "nxdn_net" : config.get('NXDN Network', 'Enable'),
            "dstar" : config.get('D-Star', 'Enable'),
            "dstar_net" : config.get('D-Star Network', 'Enable'),
            "system_fusion" : config.get('System Fusion', 'Enable'),
            "system_fusion_net" : config.get('System Fusion Network', 'Enable'),
            "pocsag" : config.get('POCSAG', 'Enable'),
            "pocsag_net" : config.get('POCSAG Network', 'Enable'),
        }
    except:
        distilled_config['network_summary'] = dict()

    config = configparser.ConfigParser()
    config.read('/etc/pistar-release')
    distilled_config['pistar_image'] = config._sections['Pi-Star']

    return distilled_config

############################
# Update functions and stuff
############################
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

def update_pistar_fork(manifest):
    """
    update the dashboard code
    """
    ##########
    # Download
    dashboard_filename = 'dashboard.tar.gz'

    latest_tag = manifest['latest_version']
    latest_tarball = manifest['version_map'][latest_tag]['url']
    latest_tarball_md5 = manifest['version_map'][latest_tag]['md5']

    logger.debug("Dashboard md5sum {} remote md5sum {}".format(md5(dashboard_filename), latest_tarball_md5))
    if md5(dashboard_filename) == latest_tarball_md5:
        UPDATE = False
        logger.info("Dashboard is up to date!")
    else:
        UPDATE = True
        try:
            os.unlink(dashboard_filename)
        except:
            pass
        logger.info("Dashboard downloading {}".format(latest_tarball))
        download_file(latest_tarball, dashboard_filename)

    #########
    # Update!
    if UPDATE:
        logger.info("DXMINI dashboard tar extracting")
        shutil.rmtree('./htdocs')
        tf = tarfile.open(dashboard_filename)
        tf.extractall("./htdocs")

def update_shell_scripts(manifest):
    """
    update the update shell script wrapper
    """
    updater_filename = "dxmini-update"

    ##########
    # Download
    latest_script = manifest['latest_script']
    latest_script_md5 = manifest['latest_script_md5']

    logger.debug("Script md5sum {} remote md5sum {}".format(md5(updater_filename), latest_script_md5))
    if md5(updater_filename) == latest_script_md5:
        logger.info("Update script is up to date!")
    else:
        try:
            os.unlink(updater_filename)
        except:
            pass
        logger.info("Update script downloading {}".format(latest_script))
        download_file(latest_script, updater_filename)

    #########
    # Update!

def update_python_agent(manifest):
    latest_python_agent = manifest['latest_python_agent']
    p = subprocess.Popen("dxmini --version", stdout=subprocess.PIPE, shell=True)
    (current_version, err) = p.communicate()
    # python3 dxmini-update_python_agent-0.0.1/setup.py install
    logger.debug("Python agent local ver {} remote ver {}".format(current_version.strip(), latest_python_agent))

    if StrictVersion(current_version) != StrictVersion(latest_python_agent):
        logger.info("Python agent needs to update.")
        # Download agent
        REPO_PATH = "https://github.com/jondkelley/dxmini-update_python_agent/archive/{}.tar.gz".format(latest_python_agent)
        download_file(REPO_PATH, 'dxmini-update_python_agent.tar.gz')
        tf = tarfile.open('dxmini-update_python_agent.tar.gz')
        tf.extractall(".")

        # Install new agent
        logger.info("Updating agent with setup.py")
        p = subprocess.Popen("python3 dxmini-update_python_agent-{}/setup.py install".format(latest_python_agent), stdout=subprocess.PIPE, shell=True)
        (out, err) = p.communicate()
        print(out)
        logger.info("Python agent update complete!")
    else:
        logger.info("Python agent is up to date!")

class AgentCommand():
    """dxmini agent
    Argument:
        args (dict): A dictionary returned by docopt afte CLI is parsed
    """
    def __init__(self, args):
        self.args = args
        print_arguements(args)

    def provision(self):
        if not os.path.isfile('/.activate'):
            touch('/.activate')
        else:
            logger.error("Device already activated")

        ## Generate serial number

        if not os.path.isfile('/etc/dxmini_serial'):
            with open('/etc/dxmini_serial', 'w') as f:
                #json.dump(data, codecs.getwriter('utf-8')(f), ensure_ascii=False)
                f.write(serial_generator())
        else:
            logger.error("Support tag already generated")

    def update(self):
        """
        update dxmini
        """

        r = requests.get(DXMINI_MANIFEST_URL)
        manifest = r.json()
        if manifest['_self_federated']:
            r = requests.get(manifest['_self_federated_url'])
            manifest = r.json()
        else:
            logger.debug("Federation is not active; using github for manifest")

        print(json.dumps(manifest, indent=3))
        update_python_agent(manifest)
        update_shell_scripts(manifest)
        update_pistar_fork(manifest)

    def ping(self):
        """
        pings the dxmini registration service
        """
        announce_client()

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
