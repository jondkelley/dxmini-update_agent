#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""Tool to manage and update rasberry pi DXMINI devices with pi-star
This toolset written by N5IPT, Jonathan Kelley 2019
pi-star / pi-star dashboard is copyright Andy Taylor (MW0MWZ) 2014-2019

Usage:
    dxmini agent --activity
    dxmini agent --register
    dxmini agent --update_check
    dxmini agent --update_agent
    dxmini agent --update_web
    dxmini agent --provision
    dxmini agent --version
    dxmini agent -h

"""

from configparser import (ConfigParser, MissingSectionHeaderError,
                          ParsingError, DEFAULTSECT)
from collections import defaultdict
from dateutil import parser
from distutils.version import StrictVersion
from docopt import docopt
from dxmini import DXMINI_MANIFEST_URL
from dxmini import __version__ as VERSION
from dxmini.lib.utils import AnsiColor as color
from dxmini.lib.utils import get_arg_option
from dxmini.lib.utils import print_arguements
from os import environ
from subprocess import Popen, PIPE
from uptime import uptime
import configparser
import fileinput
import hashlib
import json
import logging
import os
import platform
import requests
import shutil
import socket
import stat
import subprocess
import subprocess
import sys
import tarfile
import time
import uuid
logger = logging.getLogger(__name__)
os.chdir('/')

def flash_writable(mntpoint):
    """
    return if root device is writable using procfs
    """
    mounts = dict()
    with open('/proc/mounts','r') as f:
        for partition in f.readlines():
            mount = partition.split()[1]
            mode = partition.split()[3].split(',')[0]
            opts = partition.split()[3].split(',')
            mounts[mount] = mode
    if mounts.get(mntpoint, None):
        if mounts.get(mntpoint, None) == "rw":
            return True
        else:
            return False
    else:
        logger.error("root partition missing")
        return False

class MicroSdCard():
    """
    context manager to mount / dismount flash device
    """

    def __init__(self, mnt):
        self.mnt = mnt

    def __enter__(self):
        self.keep_readwrite_mode = flash_writable(self.mnt)
        if not flash_writable(self.mnt):
            logger.warn("{} : remounting flash in write mode".format(self.mnt))
            p = subprocess.Popen("mount -o remount,rw {}".format(self.mnt), stdout=subprocess.PIPE, shell=True)
            (out, err) = p.communicate()
        else:
            logger.warn("{} : flash already in write mode".format(self.mnt))

    def __exit__(self, *args):
        # don't do anything if the device was never in readonly mode
        if not self.keep_readwrite_mode:
            logger.warn("{} : remounting flash in read mode".format(self.mnt))
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

def mk_ping_crontab():
    """
    sets up hourly dxmini registration update
    """
    frequency = "daily"
    cronfile = "/etc/cron.{sched}/dxmini_registration".format(sched=frequency)
    if os.path.isfile(cronfile):
        logger.info("{crontab} : crontab already exists, skipping installe".format(crontab=cronfile))
    else:
        logger.info("{crontab} : installing crontab".format(crontab=cronfile))
        crontab = (
                "#!/bin/bash" "\n"
                "# Update the DXMINI registration service" "\n"
                "# while sleeping randomly over 2 hours to distribute load" "\n"
                "sleep $[ ( $RANDOM % 7200 )  + 30 ]s" "\n"
                "sudo dxmini agent --register" "\n"
                )
        with open(cronfile,"w") as fi:
            fi.write(crontab)
        os.chmod(cronfile, 755);

##########################
# activity log functions and stuff
##########################

def fetch_activity():
    """
    fetches link activites
    """
    records = dict()
    records['DExtra'] = list()
    records['Repeater'] = list()
    #
    with open('/var/log/pi-star/Headers.log',"r") as fi:
        try:
            for line in fi:
                if "DExtra" in line:
                    introspect0 = line.split(' ')
                    date = introspect0[0]
                    time = introspect0[1].rstrip(':')
                    introspect1 = line.split(':')
                    fieldmy = introspect1[4].rstrip(' Your').strip().split(' ')[0]
                    fieldmy1 = fieldmy.split('/')[0].strip().split(' ')[0]
                    try:
                        fieldmy2 = fieldmy.split('/')[1].strip().split(' ')[0]
                    except IndexError:
                        fieldmy2 = None
                    fieldur = introspect1[5].rstrip('Rpt1').strip()
                    fieldrpt1 = introspect1[6].rstrip('Rpt2').strip()
                    fieldrpt1 = { "call": fieldrpt1.split(' ')[0], "interface": fieldrpt1.strip().split(' ')[1] }
                    fieldrpt2 = introspect1[7].rstrip('Flags').strip()
                    fieldrpt2 = { "call": fieldrpt2.strip().split(' ')[0], "interface": fieldrpt2.split(' ')[1] }
                    fieldflags1 = introspect1[8]
                    fieldflags2 = introspect1[9]
                    fieldflags = "{}{}".format(fieldflags1, fieldflags2).split('(')[0].strip().split(' ')
                    source = "{}:{}".format(fieldflags1, fieldflags2).split('(')[1].strip().rstrip(')')
                    datetime = "{} {}".format(date, time)
                    dt = int(parser.parse(datetime).timestamp())
                    records['DExtra'].append({"dt": dt, "datetime": datetime, "my": {"raw": fieldmy, "call": fieldmy1, "suffix": fieldmy2}, "ur": fieldur, "rpt1": fieldrpt1, "rpt2": fieldrpt2, "flags": fieldflags, "source": source})
                elif "Repeater header" in line:
                    introspect0 = line.split(' ')
                    date = introspect0[0]
                    time = introspect0[1].rstrip(':')
                    introspect1 = line.split(':')
                    fieldmy = introspect1[4].rstrip(' Your').strip()
                    fieldmy1 = fieldmy.split('/')[0].strip()
                    try:
                        fieldmy2 = fieldmy.split('/')[1].strip().split(' ')[0]
                    except IndexError:
                        fieldmy2 = None
                    fieldur = introspect1[5].rstrip('Rpt1').strip()
                    fieldrpt1 = introspect1[6].rstrip('Rpt2').strip()
                    fieldrpt1 = { "call": fieldrpt1.split(' ')[0], "interface": fieldrpt1.strip().split(' ')[1] }
                    fieldrpt2 = introspect1[7].rstrip('Flags').strip()
                    fieldrpt2 = { "call": fieldrpt2.strip().split(' ')[0], "interface": fieldrpt2.split(' ')[1] }
                    fieldflags1 = introspect1[8]
                    fieldflags2 = introspect1[9]
                    fieldflags = "{}{}".format(fieldflags1, fieldflags2).split('(')[0].strip().split(' ')
                    source = "{}:{}".format(fieldflags1, fieldflags2).split('(')[1].strip().rstrip(')')
                    datetime = "{} {}".format(date, time)
                    dt = int(parser.parse(datetime).timestamp())
                    records['Repeater'].append({"dt": dt, "datetime": datetime, "my": {"raw": fieldmy, "call": fieldmy1, "suffix": fieldmy2}, "ur": fieldur, "rpt1": fieldrpt1, "rpt2": fieldrpt2, "flags": fieldflags, "source": source})
        except:
            pass
    return records

##########################
# ping functions and stuff
##########################
class StrictConfigParser(ConfigParser):
    """
    transform ini files into python dictionaries
    """
    def _read(self, fp, fpname):
        cursect = None                        # None, or a dictionary
        optname = None
        lineno = 0
        e = None                              # None, or an exception
        while True:
            line = fp.readline()
            if not line:
                break
            lineno = lineno + 1
            # comment or blank line?
            if line.strip() == '' or line[0] in '#;':
                continue
            if line.split(None, 1)[0].lower() == 'rem' and line[0] in "rR":
                # no leading whitespace
                continue
            # continuation line?
            if line[0].isspace() and cursect is not None and optname:
                value = line.strip()
                if value:
                    cursect[optname].append(value)
            # a section header or option header?
            else:
                # is it a section header?
                mo = self.SECTCRE.match(line)
                if mo:
                    sectname = mo.group('header')
                    if sectname in self._sections:
                        raise ValueError('Duplicate section %r' % sectname)
                    elif sectname == DEFAULTSECT:
                        cursect = self._defaults
                    else:
                        cursect = self._dict()
                        ##cursect['__python_style_key__'] = sectname.lower().replace(' ', '_')
                        self._sections[sectname] = cursect
                    # So sections can't start with a continuation line
                    optname = None
                # no section header in the file?
                elif cursect is None:
                    raise MissingSectionHeaderError(fpname, lineno, line)
                # an option line?
                else:
                    try:
                        mo = self._optcre.match(line)   # 2.7
                    except AttributeError:
                        mo = self.OPTCRE.match(line)    # 2.6
                    if mo:
                        optname, vi, optval = mo.group('option', 'vi', 'value')
                        optname = self.optionxform(optname.rstrip())
                        # This check is fine because the OPTCRE cannot
                        # match if it would set optval to None
                        if optval is not None:
                            if vi in ('=', ':') and ';' in optval:
                                # ';' is a comment delimiter only if it follows
                                # a spacing character
                                pos = optval.find(';')
                                if pos != -1 and optval[pos - 1].isspace():
                                    optval = optval[:pos]
                            optval = optval.strip()
                            # allow empty values
                            if optval == '""':
                                optval = ''
                            cursect[optname] = [optval]
                        else:
                            # valueless option handling
                            cursect[optname] = optval
                    else:
                        # a non-fatal parsing error occurred.  set up the
                        # exception but keep going. the exception will be
                        # raised at the end of the file and will contain a
                        # list of all bogus lines
                        if not e:
                            e = ParsingError(fpname)
                        e.append(lineno, repr(line))
        # if any parsing errors occurred, raise an exception
        if e:
            raise e

        # join the multi-line values collected while reading
        all_sections = [self._defaults]
        all_sections.extend(self._sections.values())
        for options in all_sections:
            for name, val in options.items():
                if isinstance(val, list):
                    options[name] = '\n'.join(val)

    def dget(self, section, option, default=None, type=str):
        if not self.has_option(section, option):
            return default
        if type is str:
            return self.get(section, option)
        elif type is int:
            return self.getint(section, option)
        elif type is bool:
            return self.getboolean(section, option)
        else:
            raise NotImplementedError()

def load_ini_as_dict(infile):
    """
    loads an ini file as a dictionary avoiding the load of passwords
    """
    cfg = StrictConfigParser()
    config = {}
    try:
        with open(infile) as fi:
            cfg.readfp(fi)
    except:
        return config

    for section in cfg.sections():
        config[section] = {}
        for name, value in cfg.items(section):
            if "pass" in name.lower():
                value = "###__REDACTED__###"
            value = value.strip("\"")
            value = "".join(value)
            ###section_new = section.lower().replace(' ', '_')
            config[section][name] = [x.strip() for x in value.split() if x]
            if len(config[section][name]) == 1:
                config[section][name] = config[section][name][0]
            elif len(config[section][name]) == 0:
                config[section][name] = ''
    return config

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

def get_temp():
    """
    returns system temp
    """
    logger.info("Reading  CORE TEMP...")
    with open("/sys/class/thermal/thermal_zone0/temp") as f:
        CPUTemp = f.read()
        F = str(int(CPUTemp)/1000.0 * 1.8 + 32)
        C = (float(F) - 32) * 5.0/9.0
    return F, C

def get_hostname():
    """
    return system hostname
    """
    return socket.gethostname()

def uptime1():
    '''
    Return uptimes based on seconds since last boot
    '''
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
        seconds = str(int(uptime_seconds % 60))
        minutes = str(int(uptime_seconds /60 % 60))
        hours = str(int(uptime_seconds / 60 / 60 % 24))
        days = str(int(uptime_seconds / 60 /60 / 24))
        # Time unit strings
        time_d = ' days, '
        time_h = ' hours, '
        time_m = ' minutes'
        time_s = ' seconds.'
        # Change time strings for lower units, prepend zeros
    if int(days) == 1:
        time_d = ' day, '
    if int(hours) <= 9:
        hours = '0' + hours
        if int(hours) == 1:
            time_h = 'hour '
    if int(minutes) <= 9:
        minutes = '0' + minutes
        if int(minutes) == 1:
            time_m = ' minute '
    if int(seconds) <= 9:
        seconds = '0' + seconds
        if int(seconds) == 1:
            time_s = ' second.'

    #print("")
    #print(days + time_d + hours + ':' + minutes + ':' + seconds)
    #print('Uptime is ' +days + time_d + hours + time_h + minutes + time_m +' and ' + seconds + time_s)
    return days, hours, minutes, seconds

def get_gateway_ping():
    """
    pings the gateway to get an idea of lan quality
    """
    logger.info("Reading  GW LATENCY...")
    cmd = """gw=$(route -n | grep UG | awk '{ print $2 }'); ping -c1 $gw | grep '64 bytes'| cut -d'=' -f4"""
    return subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

def get_internet_ping():
    """
    pings the internet to get an idea of wan quality
    """
    logger.info("Reading  LATENCY...")
    cmd = """ping -c1 dxmini.com| grep '64 bytes'| cut -d'=' -f4"""
    return subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

def uptime():
    """
    return raspi uptime
    """
    logger.info("Reading  UPTIME")
    return float(subprocess.check_output(['cat', '/proc/uptime']).decode('utf-8').split()[0])

def get_service_tag():
    """
    returns service tag from flash memory
    generates one if it's not found
    """
    serialfile = '/etc/dxmini_serial'
    if os.path.isfile(serialfile):
        logger.info("Reading  SERVICE_TAG...")
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return int(serial)
    else:
        serial = "".join(str(uuid.uuid4()).split('-')[3:]).upper()
        logger.warn("Generating new DXMNI service_tag {}".format(serial))
        serial = str(int(serial, 16))
        with open(serialfile,"w") as fi:
            fi.write(serial)
            fi.close()
        return int(serial)

def get_upnp_settings():
    """
    retrieves current upnp configurations
    """
    upnp_enabled_cmd = """/bin/grep '$DAEMON -a' /usr/local/sbin/pistar-upnp.service | /bin/grep -v -e '^#' | /usr/bin/awk '{ print $4 " " $5 " "  $6}'"""
    upnp_disabled_cmd = """/bin/grep '$DAEMON -a' /usr/local/sbin/pistar-upnp.service | /bin/grep -e '^#' | /usr/bin/awk '{ print $5 " " $6 " "  $7}'"""
    if os.path.isfile('/usr/local/sbin/pistar-upnp.service'):
        enabled_upnp = subprocess.check_output(upnp_enabled_cmd, shell=True).decode('utf-8')
        disabled_upnp = subprocess.check_output(upnp_disabled_cmd, shell=True).decode('utf-8')
        enabled_ports = {'UDP': [], 'TCP': []}
        disabled_ports = {'UDP': [], 'TCP': []}
        for line in enabled_upnp.rstrip().split('\n'):
            fields = line.split()
            inside = int(fields[0])
            outside = int(fields[1])
            proto = fields[2]
            enabled_ports[proto].append({"in": inside, "out": outside})
        for line in disabled_upnp.rstrip().split('\n'):
            fields = line.split()
            inside = int(fields[0])
            outside = int(fields[1])
            proto = fields[2]
            disabled_ports[proto].append({"in": inside, "out": outside})
        return {"enabled": enabled_ports, "disabled": disabled_ports}
    else:
        return dict()

def get_dxmini_panel_version():
    """
    ew this is hacky
    """
    logger.info("Reading  PHP_APPLICATION_VERSION_DATA...")
    r = requests.get('http://localhost/config/version.php')
    resp = r.json()
    return (resp['VENDOR_PANEL_VERSION'], resp['VENDOR_PANEL_REVISION'], resp['PISTAR_VERSION'])

def get_model():
    """
    returns model from flash
    """
    logger.info("Reading  DEVICE_MODEL...")
    serialfile = '/etc/dxmini_model'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial.strip()
    else:
        return None

def get_timezone():
    """return tzinfo"""
    logger.info("Reading  TIMEZONE...")
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
    logger.info("Reading  DEVICE_REVISION...")
    serialfile = '/etc/dxmini_revision'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial.strip()
    else:
        return None

def get_issue():
    """
    returns distro from /etc/issue
    """
    logger.info("Reading  DEVICE_ISSUE...")
    serialfile = '/etc/issue.net'
    if os.path.isfile(serialfile):
        with open(serialfile,"r") as fi:
            serial = fi.read()
            return serial.strip()
    else:
        return None

def get_historical_calls(mmdvm_config):
    """
    get current call
    """

    histuser_file = '/etc/.callsign_history'
    if not os.path.isfile(histuser_file):
        logger.info("Scheduling rebuild of callsign index")
        history = {"first_call": get_current_call(mmdvm_config), "callsign_history": [get_current_call(mmdvm_config)]}
        with open(histuser_file,"w") as fi:
            logger.info("Build new callsign index")
            fi.write(json.dumps(history, indent=3))
            return history
    else:
        with open(histuser_file,"r") as fi:
            history = json.loads(fi.read())
            if get_current_call(mmdvm_config) not in history['callsign_history']:
                logger.info("Adding new CALL")
                history['callsign_history'].append(get_current_call(mmdvm_config))
                with open(histuser_file,"w") as fi:
                    logger.info("Write new callsign index")
                    fi.write(json.dumps(history, indent=3))
                    return history
            else:
                logger.info("Reading  CALLSIGN...")
                return history

def get_historical_rids(mmdvm_config):
    """
    get historical radio ids
    """
    histuser_file = '/etc/.rid_history'
    if not os.path.isfile(histuser_file):
        logger.info("Need to build DMR_ID index")
        history = {"first_rid": get_current_rid(mmdvm_config), "rid_history": [get_current_rid(mmdvm_config)]}
        with open(histuser_file,"w") as fi:
            logger.info("Build new DMR_ID index")
            fi.write(json.dumps(history, indent=3))
            return history
    else:
        with open(histuser_file,"r") as fi:
            history = json.loads(fi.read())
            if get_current_rid(mmdvm_config) not in history['rid_history']:
                logger.info("Adding new DMR_ID")
                history['rid_history'].append(get_current_rid(mmdvm_config))
                with open(histuser_file,"w") as fi:
                    logger.info("Write new DMR_ID index")
                    fi.write(json.dumps(history, indent=3))
                    return history
            else:
                logger.info("Reading  DMR_ID...")
                return history

def get_current_call(config):
    """
    returns first call used in flash
    """
    firstuser_file = '/etc/first_user'

    first_user = config['general'].get('callsign', None)
    if first_user:
        with open(firstuser_file,"w") as fi:
            fi.write(first_user)
    else:
        return "N0CALL"
    return first_user

def get_current_rid(config):
    """
    returns current radio id
    """
    firstuser_file = '/etc/first_rid'
    first_user = config['general'].get('id', None)
    if first_user:
        with open(firstuser_file,"w") as fi:
            fi.write(first_user)
    else:
        return "0000000"
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

def get_interface():
    """
    get interface stats
    """
    logger.info("Reading  INTERFACE COUNTERS...")
    hwaddr = subprocess.check_output("ifconfig wlan0| head -1 | awk '{ print $5 }'", shell=True).decode('utf-8').strip()
    meta_1 = [{ x.strip().split('=')[0].lower().replace(' ', '_') : x.strip().split('=')[1] } for x in subprocess.check_output("iwconfig wlan0 | grep Tx-Power", shell=True).decode('utf-8').strip().split('  ')]
    meta_2 = [{ x.strip().split('=')[0].lower().replace(' ', '_') : x.strip().split('=')[1] } for x in subprocess.check_output("iwconfig wlan0 | grep 'Signal level'", shell=True).decode('utf-8').strip().split('  ')]
    meta_3 = [{ x.strip().split(':')[0].lower().replace(' ', '_') : x.strip().split(':')[1] } for x in subprocess.check_output("iwconfig wlan0 | grep 'Access Point'", shell=True).decode('utf-8').strip().split('  ')]
    meta_4 = [{ x.strip().split(':')[0].lower().replace(' ', '_') : x.strip().split(':')[1] } for x in subprocess.check_output("iwconfig wlan0 | grep 'Missed beacon'", shell=True).decode('utf-8').strip().split('  ')]
    meta_5 = [{ x.strip().split(':')[0].lower().replace(' ', '_') : x.strip().split(':')[1] } for x in subprocess.check_output("iwconfig wlan0 | grep 'nvalid crypt'", shell=True).decode('utf-8').strip().split('  ')]
    rx_packets = [{ x.split(':')[0].lower().replace(' ', '_') : x.split(':')[1]} for x in subprocess.check_output("ifconfig wlan0 | grep 'RX packets'", shell=True).decode('utf-8').strip().split(' ')[1:]]
    tx_packets = [{ x.split(':')[0].lower().replace(' ', '_') : x.split(':')[1]} for x in subprocess.check_output("ifconfig wlan0 | grep 'TX packets'", shell=True).decode('utf-8').strip().split(' ')[1:]]
    new_dict = {}
    for item in meta_1:
        for k, v in item.items():
            new_dict[k] = v
    for item in meta_2:
        for k, v in item.items():
            new_dict[k] = v
    for item in meta_3:
        for k, v in item.items():
            new_dict[k] = v
    for item in meta_4:
        for k, v in item.items():
            new_dict[k] = v
    for item in meta_5:
        for k, v in item.items():
            new_dict[k] = v
    new_dict['rx_counts'] = dict()
    for item in rx_packets:
        for k, v in item.items():
            new_dict['rx_counts'][k] = v
    new_dict['tx_counts'] = dict()
    for item in tx_packets:
        for k, v in item.items():
            new_dict['tx_counts'][k] = v
    del new_dict['access_point']
    new_dict['hwaddr_ap'] = ":".join(subprocess.check_output("iwconfig wlan0 | grep 'Access Point'", shell=True).decode('utf-8').strip().split('  ')[2].split(':')[1:]).strip().lower()
    new_dict['hwaddr'] = hwaddr.lower()
    new_dict['ipaddr'] = get_nat_ip()
    return new_dict

def get_nat_ip():
    """
    get the local address
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable, neat trick eh?
        s.connect(('10.255.255.255', 1))
        a = s.getsockname()[0]
    except:
        a = '127.0.0.1'
    finally:
        s.close()
    return a

def register_client():
    mmdvm_config = get_mmdvm_config()
    historical_calls = get_historical_calls(mmdvm_config)
    historical_rids = get_historical_rids(mmdvm_config)
    gw_ping = get_gateway_ping()
    net_ping = get_internet_ping()
    temp = get_temp()
    web_panel_version, web_panel_rev, web_panel_upstream_version = get_dxmini_panel_version()
    hello = {
        "entry": {
            "user": {
                "tz": get_timezone(),
                "activation_dt": { 'dt': get_customer_production_date(), 'datetime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(get_customer_production_date()))},
                "identities": {
                    "ham": {
                        "initial":  historical_calls['first_call'],
                        "history": historical_calls['callsign_history'],
                        "current": get_current_call(mmdvm_config),
                    },
                    "dmr": {
                        "initial":  historical_rids['first_rid'],
                        "history": historical_rids['rid_history'],
                        "current": get_current_rid(mmdvm_config),
                    },
                },
                "service_tag": get_service_tag(),
                "configuration": {
                    #"mmdvm": get_mmdvm_config(),
                    "ircdbgateway": get_ircdbgateway_config(),
                    "dstarrepeater": get_dstarrepeater_config(),
                    "dapnetgateway": load_ini_as_dict('/etc/dapnetgateway'),
                    "dstar-radio.mmdvmhost": load_ini_as_dict('/etc/dstar-radio.mmdvmhost'),
                    "pistar-remote": load_ini_as_dict('/etc/pistar-remote'),
                    "ysf2dmr": load_ini_as_dict('/etc/ysf2dmr'),
                    "ysf2nxdn": load_ini_as_dict('/etc/ysf2nxdn'),
                    "ysf2p25": load_ini_as_dict('/etc/ysf2p25'),
                    "ysfgateway": load_ini_as_dict('/etc/ysfgateway'),
                    "pistar-keeper": load_ini_as_dict('/etc/pistar-keeper'),
                    "pistar-remote": load_ini_as_dict('/etc/pistar-remote'),
                    "p25gateway": load_ini_as_dict('/etc/p25gateway'),
                    "mmdvmhost": load_ini_as_dict('/etc/mmdvmhost')
                }
            },
            "network": {
                "upnp": get_upnp_settings(),
                "latency": {
                    "lan": { "scale": gw_ping.split(" ")[1], "value": gw_ping.split(" ")[0]},
                    "wan": { "scale": net_ping.split(" ")[1], "value": net_ping.split(" ")[0]},
                },
                "hostname": get_hostname(),
                "interface": get_interface(),
            },
            "dxmini": {
                "system_temp": { "f": temp[0], "c": temp[1] },
                "pistar_version": get_pistar_image_version(),
                "os_version": get_issue(),
                "web_version": {"version": web_panel_version, "rev": web_panel_rev, "upstream_pistar_release": web_panel_upstream_version},
                "device_version": {"rev": get_revision(), "model": get_model() },
                "device_uptime": { "days": uptime1()[0], "hours": uptime1()[1], "minutes": uptime1()[2], "seconds": uptime1()[3], "total_seconds": uptime() },
            }
        }
    }
    try:
        logger.info("Sending registration...")
        client_registration_url = "https://elmers.news/dxm-api/v1.0/register"
        logger.debug("JSON Payload : {}".format(hello))
        announce = requests.post(client_registration_url, data=json.dumps(hello), verify=True, timeout=5)
        if not announce.status_code == requests.codes.ok:
            logger.error("dxmini api error, http status code fail {}".format(announce.status_code))
    except requests.exceptions.HTTPError as errh:
        logger.error("dxmini api error : HTTPError {}".format(errh))
    except requests.exceptions.ConnectionError as errc:
        logger.error("dxmini api error : ConnectionError {}".format(errc))
    except requests.exceptions.Timeout as errt:
        logger.error("dxmini api error : Timeout {}".format(errt))
    except requests.exceptions.RequestException as err:
        logger.error("dxmini api error : RequestException {}".format(err))

def register_activity():
    service_tag = get_service_tag()
    hello = {
        "tz": get_timezone(),
        "logs": fetch_activity()
    }
    try:
        logger.info("Sending activity...")
        client_registration_url = "https://elmers.news/dxm-api/v1.0/activity/{}".format(service_tag)
        logger.info("JSON Payload : {}".format(hello))
        announce = requests.post(client_registration_url, data=json.dumps(hello), verify=True, timeout=5)
        if not announce.status_code == requests.codes.ok:
            logger.error("dxmini api error, http status code fail {}".format(announce.status_code))
    except requests.exceptions.HTTPError as errh:
        logger.error("dxmini api error : HTTPError {}".format(errh))
    except requests.exceptions.ConnectionError as errc:
        logger.error("dxmini api error : ConnectionError {}".format(errc))
    except requests.exceptions.Timeout as errt:
        logger.error("dxmini api error : Timeout {}".format(errt))
    except requests.exceptions.RequestException as err:
        logger.error("dxmini api error : RequestException {}".format(err))

def get_pistar_image_version():
    """
    retrieve some settings from the RPi base image
    """
    #############################
    config = configparser.ConfigParser()
    logger.info("Reading  pistar-release...")
    config.read('/etc/pistar-release')
    return config._sections['Pi-Star']

def get_dstarrepeater_config():
    """
    retrieve some settings from dstarrepeater config while avoiding passwords
    """
    distilled_config = {}
    #############################
    configfile = '/etc/dstarrepeater'
    logger.info("Reading  dstarrepeater...")
    if os.path.isfile(configfile):
        with open(configfile,"r") as fi:
            for line in fi:
                key = line.split('=')[0]
                value = line.split('=')[1]
                key = key.lower().strip()
                if "pass" in key:
                    value = "###__REDACTED__###"
                distilled_config[key] = value.strip()
    else:
        logger.error("{} : file not found".format(configfile))
        return distilled_config

    return distilled_config

def get_ircdbgateway_config():
    """
    retrieve some settings from the ircdbgateway while avoiding leak of passwords
    """
    distilled_config = {}
    #############################
    configfile = '/etc/ircddbgateway'
    logger.info("Reading  ircddbgateway...")
    if os.path.isfile(configfile):
        with open(configfile,"r") as fi:
            for line in fi:
                key = line.split('=')[0]
                value = line.split('=')[1]
                key = key.lower().strip()
                if "pass" not in key:
                    distilled_config[key] = value.strip()
    else:
        logger.error("{} : file not found".format(configfile))
        return distilled_config

    return distilled_config

def get_mmdvm_config():
    """
    retrieve some settings from the mmdvm if available
    """
    distilled_config = {}
    #############################
    config = configparser.ConfigParser()
    config.read('/etc/mmdvmhost')
    logger.info("Reading  MMDVM Host Config...")
    try:
        distilled_config['general'] = config._sections['General']
    except:
        distilled_config['general'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['Info'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['info'] = mmdvm_info
    except:
        distilled_config['info'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['CW Id'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['cw_id'] = mmdvm_info
    except:
        distilled_config['cw_id'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['Modem'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['modem'] = mmdvm_info
    except:
        distilled_config['modem'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['D-Star'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['d-star'] = mmdvm_info
    except:
        distilled_config['d-star'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['DMR'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['dmr'] = mmdvm_info
    except:
        distilled_config['dmr'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['System Fusion'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['ysf'] = mmdvm_info
    except:
        distilled_config['ysf'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['P25'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['p25'] = mmdvm_info
    except:
        distilled_config['p25'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['NXDN'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['nxdn'] = mmdvm_info
    except:
        distilled_config['nxdn'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['POCSAG'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['pocsag'] = mmdvm_info
    except:
        distilled_config['pocsag'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['Nextion'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['nextion'] = mmdvm_info
    except:
        distilled_config['nextion'] = {}

    try:
        mmdvm_info = {}
        for k, v in config._sections['Remote Control'].items():
            k = k.lower()
            mmdvm_info[k] = v.strip("\"") # remove wrapping quotes on some strings
        distilled_config['remote_control'] = mmdvm_info
    except:
        distilled_config['remote_control'] = {}

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
    logger.info("Downloading {}".format(url))
    response = requests.get(url, stream=True)

    # Throw an error for bad status codes
    response.raise_for_status()

    with open(filename, 'wb') as handle:
        for block in response.iter_content(1024):
            handle.write(block)

def web_panel_updater(manifest):
    """
    update the dashboard code
    """
    ##########
    # Download
    dashboard_filename = 'dashboard.tar.gz'

    latest_tag = manifest['latest_version']
    latest_tarball = manifest['version_map'][latest_tag]['url']
    latest_tarball_md5 = manifest['version_map'][latest_tag]['md5']
    latest_revision = manifest['version_map'][latest_tag]['revision']
    latest_version = manifest['version_map'][latest_tag]['version']

    logger.debug("Dashboard md5sum {} remote md5sum {}".format(md5(dashboard_filename), latest_tarball_md5))
    web_panel_version, web_panel_rev, web_panel_upstream_version = get_dxmini_panel_version()
    if ((latest_version == web_panel_version) and int(latest_revision) <= int(web_panel_rev)):
        UPDATE = False
        logger.info("Dashboard is already up to date")
    else:
        if ((latest_version == web_panel_version) and int(latest_revision) != int(web_panel_rev)):
            logger.info("New revision found, starting update...")
        else:
            lgoger.info("New version found, starting update...")

        UPDATE = True
        try:
            os.unlink(dashboard_filename)
        except:
            pass
        logger.info("Found {} downloading...".format(latest_tarball.split('/')[-1:][0]))
        download_file(latest_tarball, dashboard_filename)

    #########
    # Update!
    if UPDATE:
        logger.info("DXMINI control panel extracting from tar archive")
        try:
            shutil.rmtree('./htdocs')
            shutil.rmtree('/var/www/dashboard')
        except:
            pass
        tf = tarfile.open(dashboard_filename)
        tf.extractall("./htdocs")
        ##os.unlink("/var/www/dashboard")
        os.rename("./htdocs/htdocs", "/var/www/dashboard")

def preinst_script(manifest):
    """
    update the update shell script wrapper
    """
    updater_filename = "postinst.sh"

    ##########
    # Download
    latest_script = manifest['preinstall']
    latest_script_md5 = manifest['preinstall_script_md5']

    logger.debug("Script md5sum {} remote md5sum {}".format(md5(updater_filename), latest_script_md5))
    if md5(updater_filename) == latest_script_md5:
        logger.info("Preinstall script is up to date!")
    else:
        try:
            os.unlink(updater_filename)
        except:
            pass
        logger.info("Update script downloading {}".format(latest_script))
        download_file(latest_script, updater_filename)

    #########
    # Update!
    cmd = "sudo mv {name} /usr/bin; chmod 755 /usr/bin/{name}; bash -x /usr/bin/{name}".format(name=updater_filename)
    logger.info("Running pre install scripts...")
    output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
    logger.warn(output)


def postinst_script(manifest):
    """
    update the update shell script wrapper
    """
    updater_filename = "postinst.sh"

    ##########
    # Download
    latest_script = manifest['postinstall']
    latest_script_md5 = manifest['postinstall_script_md5']

    logger.debug("Script md5sum {} remote md5sum {}".format(md5(updater_filename), latest_script_md5))
    if md5(updater_filename) == latest_script_md5:
        logger.info("Postinstall script is up to date!")
    else:
        try:
            os.unlink(updater_filename)
        except:
            pass
        logger.info("Postinstall script downloading {}".format(latest_script))
        download_file(latest_script, updater_filename)

    #########
    # Update!
    cmd = "sudo mv {name} /usr/bin; chmod 755 /usr/bin/{name}; bash -x /usr/bin/{name}".format(name=updater_filename)
    logger.info("Running post install scripts...")
    output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
    #logger.warn(output)
    logger.info("Install complete")

def agent_updater_agent_thing(manifest):
    latest_python_agent = manifest['latest_python_agent']
    p = subprocess.Popen("dxmini --version", stdout=subprocess.PIPE, shell=True)
    (current_version, err) = p.communicate()
    # python3 dxmini-agent_updater_agent_thing-0.0.1/setup.py install
    current_version = current_version.decode("utf-8").strip()
    latest_python_agent = str(latest_python_agent).strip()
    logger.debug("Python agent local ver {} remote ver {}".format(current_version, latest_python_agent))
    if StrictVersion(current_version) != StrictVersion(latest_python_agent):
        logger.info("Python agent needs to update.")
        # Download agent
        cmd = "rm -rf /dxmini-update_agent"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        cmd = "git clone https://github.com/jondkelley/dxmini-update_agent.git"
        logger.info("{}".format(cmd))
        output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        # REPO_PATH = "https://github.com/jondkelley/dxmini-update_agent/archive/{}.tar.gz".format(latest_python_agent)
        # download_file(REPO_PATH, 'dxmini-agent.tar.gz')
        # tf = tarfile.open('dxmini-agent.tar.gz')
        # tf.extractall(".")

        # Install new agent
        logger.info("Running setup.py install")
        #p = subprocess.Popen("sudo python3 dxmini-update_agent-{}/setup.py install".format(latest_python_agent), stdout=subprocess.PIPE, shell=True)
        #(out, err) = p.communicate()
        #print(out)
        cmd = "cd /dxmini-update_agent/; python3 setup.py install".format(latest_python_agent)
        output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        logger.warn("Python {}".format(output))
        cmd = "rm -rf /dxmini-update_agent"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        logger.info("Removing install files {}".format(output))
        logger.info("Agent update complete. Thanks for updating me!")
    else:
        logger.info("Agent is up to date!")

class RootCommand():
    """
    agent commands for docopt
    """
    def __init__(self, args):
        self.args = args

    def provision(self):
        with MicroSdCard("/"):
            if not os.path.isfile('/.in_production'):
                touch('/.in_production')
            else:
                logger.info("Registration file, OK")

            ## Generate serial number

            if not os.path.isfile('/etc/dxmini_serial'):
                newly_service_tag = get_service_tag()
                logger.info("Hooray, new service tag number {tag}".format(tag=newly_service_tag))
            else:
                logger.info("Support file, OK")

    def update_agent(self):
        """
        download and install latest agent
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

            #print(json.dumps(manifest, indent=3))
            agent_updater_agent_thing(manifest)

    def update_web(self):
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

            #print(json.dumps(manifest, indent=3))
            preinst_script(manifest)
            web_panel_updater(manifest)
            postinst_script(manifest)

    def register(self):
        """
        registers the dxmini
        """
        with MicroSdCard("/"):
            mk_ping_crontab()
            register_client()

    def activity(self):
        """
        registers the dxmini activity
        """
        register_activity()

    def version(self):
        """
        print module version and exit
        """
        print(VERSION)
        exit(0)

def main():
    """Parse the CLI"""
    arguments = docopt(__doc__)

    cmd = RootCommand(arguments)
    method = get_arg_option(arguments)
    getattr(cmd, method)()

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
