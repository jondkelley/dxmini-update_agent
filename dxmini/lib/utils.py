#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8


def get_arg_option(args):
    for key, value in args.items():
        if (key != '--force' and key.startswith('--') and
                isinstance(value, bool) and value):
            return key.replace('-', '')

def shell_command(command):
    """
    runs a command with subprocess
    returns a tuple (exitcode, stdout, stderr)
    """
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (stdout, stderr) = p.communicate()
    exit_code = p.wait()
    return (exit_code, stdout, stderr)

def print_arguements(args):
    """
    prints a pretty format version of yorktown arguements
    """
    dash = '-' * 40
    print(AnsiColor.red)
    print("{}\n              Arguements\n{}".format(dash, dash))
    print("{}{{{}".format(AnsiColor.blue, AnsiColor.yellow))
    for key, val in args.items():
        print('     {:<10s}: {:<10s}'.format(key, str(val)))
    print("{}}}".format(AnsiColor.blue))
    print(AnsiColor.red)
    print("{}{}".format(dash, AnsiColor.end))

# class AnsiColor(object):
#     """
#     life is better in color
#     """
#     header = '\033[95m'
#     blue = '\033[1;94m'
#     green = '\033[1;92m'
#     yellow = '\033[93m'
#     red = '\033[91m'
#     magenta = '\033[91m'
#     end = '\033[0m'
#     bold = '\033[1m'
#     underline = '\033[4m'

class AnsiColor(object):
    """
    life is better in color
    """
    header = ''
    blue = ''
    green = ''
    yellow = ''
    red = ''
    magenta = ''
    end = ''
    bold = ''
    underline = ''
