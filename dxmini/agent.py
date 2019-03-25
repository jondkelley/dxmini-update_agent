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

from uptime import uptime
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
import stat
import logging
import requests
import json
from subprocess import Popen, PIPE
from os import environ
import hashlib
import tarfile
import time
import uuid
import platform
import fileinput

logger = logging.getLogger(__name__)

class MicroSdCard():
    """
    context manager handles mounting / dismounting the DXMINI filesystem
    """

    def __init__(self, mnt):
        self.mnt = mnt

    def __enter__(self):
        # TODO some exception handling please, what is this??
        p = subprocess.Popen("mount -o remount,rw {}".format(self.mnt), stdout=subprocess.PIPE, shell=True)
        (out, err) = p.communicate()

    def __exit__(self, *args):
        # TODO some exception handling please, what is this??
        p = subprocess.Popen("mount -o remount,ro {}".format(self.mnt), stdout=subprocess.PIPE, shell=True)
        (out, err) = p.communicate()

################################
# Initial provisioning and stuff
################################

def serial_generator():
    """
    function generates service tag number as string
    """
    return str(
            int(
                "".join(str(uuid.uuid4()).split('-')[:3]
                ),
                16
            )
        )

def touch(path):
    with open(path, 'a'):
        os.utime(path, None)

# def insert_line_after(fi, line_to_find):
#     """ insert line after search text """
#     if os.path.isfile(fi):
#         for line in fileinput.FileInput(file_path,inplace=1):
#             if "TEXT_TO_SEARCH" in line:
#                 line=line.replace(line,line+"NEW_TEXT")
#             print line,
#     pass

def mk_ping_crontab():
    """
    sets up hourly dxmini registration update
    """
    frequency = "daily"
    cronfile = "/etc/cron.{sched}/dxmini_updates".format(sched=frequency)
    if os.path.isfile(cronfile):
        logger.info("{crontab} : crontab already exists, skipping install (SDSAVER)".format(crontab=cronfile))
    else:
        logger.info("{crontab} : installing crontab".format(crontab=cronfile))
        crontab = (
                "#!/bin/bash" "\n"
                "# Update the DXMINI registration service" "\n"
                "# while sleeping randomly over 2 hours to distribute load" "\n"
                "sleep $[ ( $RANDOM % 7200 )  + 30 ]s" "\n"
                "sudo dxmini agent --ping" "\n"
                )
        with open(cronfile,"w") as fi:
            fi.write(crontab)

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
    return subprocess.check_output(['cat', '/proc/uptime']).decode('utf-8').split()[0]

def get_service_tag():
    """
    returns service tag from flash memory
    generates one if it's not found
    """
    serialfile = '/etc/dxmini_serial'
    if os.path.isfile(serialfile):
        logger.info("Returning SERVICE_TAG")
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial
    else:
        serial = "".join(str(uuid.uuid4()).split('-')[3:]).upper()
        logger.warn("Generating new DXMNI service_tag {}".format(serial))
        serial = str(int(serial, 16))
        with open(serialfile,"w") as fi:
            fi.write(serial)
            fi.close()
        return serial

def get_upnp_settings():
    """
    retrieves current upnp configurations
    """
    upnp_enabled_cmd = """/bin/grep '$DAEMON -a' /usr/local/sbin/pistar-upnp.service  | /bin/grep -e '^#' | /usr/bin/awk '{ print "inside=" $5 ",outside=" $6 ",proto=" $7}'"""
    upnp_disabled_cmd = """/bin/grep '$DAEMON -a' /usr/local/sbin/pistar-upnp.service  | /bin/grep -v -e '^#' | /usr/bin/awk '{ print "inside=" $5 ",outside=" $5 ",proto=" $6}'"""
    if os.path.isfile('/usr/local/sbin/pistar-upnp.service'):
        enabled_upnp = subprocess.check_output(upnp_enabled_cmd, shell=True).decode('utf-8').split('\n')[:-1]
        disabled_upnp = subprocess.check_output(upnp_disabled_cmd, shell=True).decode('utf-8').split('\n')[:-1]
        struct = { "on": {}, "off": {}}
        i = 0
        for rule in enabled_upnp.split(','):
            (key, value) = rule.split('=')
            i += 1
            struct['on'][key][i] = value
        i = 0
        for rule in disabled_upnp.split(','):
            (key, value) = rule.split('=')
            i += 1
            struct['off'][key][i] = value
        return struct
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

def get_dxmini_panel_version():
    """
    ew this is hacky
    """
    logger.info("Returning DXMINI control panel version")
    cmd = """/usr/bin/curl -s http://localhost | /bin/grep 'version_panel' | /bin/grep 'pi-star' | /usr/bin/cut -d'>' -f3  | /usr/bin/awk '{ print $1 }'"""
    return subprocess.check_output(cmd, shell=True).decode('utf-8').split()[0]

def get_model():
    """
    returns model from flash
    """
    logger.info("Returning MODEL")
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
            return str(tz).strip()
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
        logger.info("Scheduling rebuild of callsign index")
        history = {"first_call": get_current_call(), "callsign_history": [get_current_call()]}
        with open(histuser_file,"w") as fi:
            logger.info("Build new callsign index")
            fi.write(json.dumps(history, indent=3))
            return history
    else:
        with open(histuser_file,"r") as fi:
            history = json.loads(fi.read())
            if get_current_call() not in history['callsign_history']:
                logger.info("Adding new CALL")
                history['callsign_history'].append(get_current_call())
                with open(histuser_file,"w") as fi:
                    logger.info("Write new callsign index")
                    fi.write(json.dumps(history, indent=3))
                    return history
            else:
                logger.info("Returning CALL")
                return history

def get_historical_rids():
    """
    get historical radio ids
    """
    histuser_file = '/etc/.rid_history'
    if not os.path.isfile(histuser_file):
        logger.info("Need to build RID index")
        history = {"first_rid": get_current_rid(), "rid_history": [get_current_rid()]}
        with open(histuser_file,"w") as fi:
            logger.info("Build new RID index")
            fi.write(json.dumps(history, indent=3))
            return history
    else:
        with open(histuser_file,"r") as fi:
            history = json.loads(fi.read())
            if get_current_rid() not in history['rid_history']:
                logger.info("Adding new RID")
                history['rid_history'].append(get_current_rid())
                with open(histuser_file,"w") as fi:
                    logger.info("Write new RID index")
                    fi.write(json.dumps(history, indent=3))
                    return history
            else:
                logger.info("Returning RID")
                return history

def get_current_call():
    """
    returns first call used in flash
    """
    firstuser_file = '/etc/first_user'

    config = get_mmdvm_config()
    first_user = config['mmdvm_general'].get('callsign', None)
    if first_user:
        with open(firstuser_file,"w") as fi:
            fi.write(first_user)
    else:
        return False
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

def get_customer_production_date():
    """
    returns when the DXMINI goes into production
    """
    serialfile = '/.in_production'
    if os.path.isfile(serialfile):
        return int(creation_date('/.in_production'))
    else:
        return None

def file_age_in_seconds(pathname):
    """
    return a files exact age in seconds
    """
    if not os.path.isfile(pathname):
        touch(pathname)
    return time.time() - os.stat(pathname)[stat.ST_MTIME]

def selfie_in():
    """
    cache local and remote interface
    """
    if not os.path.isfile('/tmp/.0'):
        touch('/tmp/.1')

    if not os.path.isfile('/tmp/.0'):
        if file_age_in_seconds('/tmp/.0') > 43200:
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
                return a
    else:
        with open("/tmp/.0", "r") as fcontext:
            a = fcontext.read()
            return a

def selfie_out():
    if not os.path.isfile('/tmp/.1'):
        touch('/tmp/.1')

    if os.path.isfile('/tmp/.1'):
        if file_age_in_seconds('/tmp/.1') > 43200:
            try:
                r = requests.get('http://ifconfig.me')
                b = r.text
            except:
                r = requests.get('http://api.dxmini.uberleet.org/dxmini-function/selfie')
                b = r.text
            with open('/tmp/.1',"w") as fi:
                i.write(b)
                return b
        else:
            with open("/tmp/.1", "r") as fcontext:
                b = fcontext.read()
    else:
        with open("/tmp/.1", "r") as fcontext:
            b = fcontext.read()
            return b

def register_client():
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
            "dashboard": str(get_dxmini_panel_version()),
            "service_tag": get_service_tag(),
            "rev": get_revision(),
            "model": get_model(),
            "customer_production_start": get_customer_production_date(),
            "device_uptime": uptime(),
            "tz": get_timezone(),
            "self_in": selfie_in(),
            "self_out": selfie_out()
        },
        "config": {
            "settings": get_mmdvm_config(),
            #"wpa_supplicant": get_wpa_supplicant(),
            "upnp": get_upnp_settings()
        },
        "image_information": get_pistar_image_version()
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

def get_pistar_image_version():
    """
    retrieve some settings from the RPi base image
    """
    distilled_config = {}
    #############################
    config = configparser.ConfigParser()
    config.read('/etc/pistar-release')
    distilled_config['pistar_image'] = config._sections['Pi-Star']

    return distilled_config

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
        mmdvm_info = {}
        for k, v in config._sections['Info'].items():
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['mmdvm_info'] = mmdvm_info
    except:
        distilled_config['mmdvm_info'] = {}

    try:
        distilled_config['networks'] = {
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
        p = subprocess.Popen("sudo python3 dxmini-update_python_agent-{}/setup.py install".format(latest_python_agent), stdout=subprocess.PIPE, shell=True)
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
        #print_arguements(args)

    def provision(self):
        if not os.path.isfile('/.in_production'):
            touch('/.in_production')
        else:
            logger.info("Registration file, OK")

        ## Generate serial number

        if not os.path.isfile('/etc/dxmini_serial'):
            newly_service_tag = get_service_tag().strip()
            logger.info("Hooray, new service tag number {tag}".format(tag=newly_service_tag))
        else:
            logger.info("Support file, OK")

    def update(self):
        """
        update dxmini
        """
        with MicroSdCard("/"):
            r = requests.get(DXMINI_MANIFEST_URL)
            manifest = r.json()
            if manifest['_self_federated']:
                try:
                    r = requests.get(manifest['_self_federated_url'])
                    manifest = r.json()
                except:
                    logger.error("Federation manifest request httpclient failure; defaulting to what github sent us")
                    pass
            else:
                logger.debug("Federation false; using github")

            print(json.dumps(manifest, indent=3))
            update_python_agent(manifest)
            update_shell_scripts(manifest)
            update_pistar_fork(manifest)

    def ping(self):
        """
        pings the dxmini registration service
        """
        with MicroSdCard("/"):
            mk_ping_crontab()
            register_client()

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
