#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

__title__ = 'dxmini'
__author__ = 'Jonathan Kelley'
__version__ = '0.0.1'
__license__ = 'FreeBSD'

DXMINI_MANIFEST_URL = "https://raw.githubusercontent.com/jondkelley/dxmini-releasemap/master/manifest.json"
DXMINI_PHP_ROOT = "/var/www/dashboard"

UPDATE_SHELL_PATH = "latest_update.sh"

MODULES = [
    'agent',
    'provision',
    'ping'
]
