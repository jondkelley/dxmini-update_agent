#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""A tool to manage deployments in a modular fashion

Usage: dxmini [-v | -h] <command> [<args>...]

Options:
  -h, --help                show this screen.
  -v, --version             show version.

Available dxmini commands:
    agent           Agent Commands
    provision       Provision

See 'dxmini help <command>' for more information on a specific command.
"""
import sys
from operator import methodcaller
from importlib import import_module
from docopt import docopt
from dxmini import __version__ as version
from dxmini import MODULES
import dxmini.lib.logginglib
import logging
logger = logging.getLogger(__name__)


def main():
    """
    parse top level CLI interface and invoke subcommands
    """
    args = docopt(__doc__, version=version, options_first=True)

    call_main = methodcaller('main')
    if args['<command>'] in MODULES:
        sub_cmd = import_module('dxmini.%s' % args['<command>'])
        call_main(sub_cmd)
    elif args['<command>'] == 'help':
        if len(args['<args>']) == 1 and args['<args>'][0] in MODULES:
            sub_cmd = import_module('dxmini.%s' % args['<args>'][0])
            call_main(sub_cmd)
        else:
            msg = "use any of {c} in help command".format(c=','.join(MODULES))
            sys.exit(msg)
    else:
        sys.exit("<{}> isn't a dxmini command. See 'dxmini --help'."
                 .format(args['<command>']))


if __name__ == '__main__':
    main()
