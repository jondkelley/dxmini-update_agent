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

MOTD_FILE = """=============================================================^[[1;32m ^[[2m$
88888888ba, 8b        d8 88b           d88 88 888b      88 88$
88      `"8b Y8,    ,8P  888b         d888 88 8888b     88 88$
88        `8b `8b  d8'   88`8b       d8'88 88 88 `8b    88 88$
88         88   Y88P     88 `8b     d8' 88 88 88  `8b   88 88$
88         88   d88b     88  `8b   d8'  88 88 88   `8b  88 88$
88         8P ,8P  Y8,   88   `8b d8'   88 88 88    `8b 88 88$
88      .a8P d8'    `8b  88    `888'    88 88 88     `8888 88$
88888888Y"' 8P        Y8 88     `8'     88 88 88      `888 88^[[0m$
=============================================================$
DXMINIM-bM-^DM-" by W9DXM$
DXMINI OS image mastered by Jonathan Kelley (N5IPT)$
Pi-Star built by Andy Taylor (MW0MWZ)$
=============================================================$
$
From the Windows Computer:$
DXMINI Dashboard:       http://dxmini/$
$
From your iPhone, iPad, Macbook, Ubuntu, Chromebook, the toaster, etc.$
DXMINI Dashboard:       http://dxmini.local/$"""
