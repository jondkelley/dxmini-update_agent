# Yorktown

```
                      |
                     -+-
                   ---#---            U.S.S. Yorktown
                   __|_|__              1943 - 1970
                   \_____/      
    _______________\_____/ _______________________________________
    ||\__||\__||\__|___  |||\__||\__||\__|___ ||\__||\__||\__|__||
    -^---------^--^----^___.-------------.___.--------.___.------
    `-------------|-------------------------------|-------------'
```

## Description

*Yorktown* is a modular approach to command automation. By placing commands in separate modules and doing dynamic imports, we will drastically increase code reliability. Modules isolate namespace to point that *if another project has a syntax error, it won't hurt you!* The libraries folder is the only point of shared namespace. This model also uses docopt to dynamically generate command arguments without fighting with argparse for hours on end.

## Code Structure

The `yorktown` project maintains an organized code structure

    ├── yorktown............................. project
    │   ├── __init__.py...................... __MODULE__
    │   ├── cli.py........................... entry point
    │   ├── demo.py.......................... module for demo command
    │   ├── gitexec.py....................... module for gitexec command
    │   ├── jenkins.py....................... module for jenkins command
    │   └── lib.............................. libraries
    │       ├── __init__.py.................. __MODULE__
    │       └── libgit.py.................... git library
    │       └── libjenkins.py................ jenkins library
    │       └── utils.py..................... utility functions

## Action Shot

![](/yorktown.png)

## Examples

### Usage

The CLI tries to be friendly, straightforward. Documentation literally turns into code by using the [docopt Python module](https://pypi.python.org/pypi/docopt). This enforces good documentation standards as well as totally removes the need to mess with argparse and subparsers.

Here is the basic syntax to start with::

    % yorktown
    Usage: yorktown [-v | -h] <command> [<args>...]

    % yorktown -h
    A tool to manage HAProxy via the stats socket.

    Usage: yorktown [-v | -h] <command> [<args>...]

    Options:
    -h, --help                show this screen.
    -v, --version             show version.

    Available yorktown commands are:
        demo     Demo example

    See 'yorktown help <command>' for more information on a specific command.

Keep reading for more details about each command.

### Commands for Demo

    % yorktown demo --helloworld [-s STRING, -n TIMES, -b BOOL]
    Hello world method

    % yorktown demo --cmd [-c CMD]
    Cmd method

    % yorktown demo -h
    Print help

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


### Commands for gitexec

    % yorktown gitexec --run [-r REPOSITORY_URL, -b BRANCH, -t TAG, -i INTERPRETER, -c COMMAND, -a ARGS, -e ENVIRONMENT]
    Runs command from a local git checkout

    % yorktown gitexec -h
    Print help

    Options:
        -h                                                 show this message
        -r REPOSITORY_URL, --repo REPOSITORY_URL           repository URL
        -b BRANCH, --branch BRANCH                         git branch to checkout (use tags/name for a tag)
        -t TAG, --tag TAG                                  git tag to checkout
        -i INTERPRETER, --interpreter INTERPRETER          optional interpreter i.e. python, bash, php
        -c COMMAND, --command COMMAND                      command to run under branch
        -a ARGS, --arguements ARGS                         arguements to pass as a string (use quotes) i.e. ("-i -o gcc.so")
        -e ENVIRONMENT, --environment ENVIRONMENT          environment variables to export i.e. (HOME=/,CWD=/)

### Commands for jenkins

    % yorktown jenkins --showconfig [-j JOBNAME, -u USER, --pass PASSWORD]
    Prints a jenkins XML configuration

    % yorktown jenkins --build [-j JOBNAME, -p PARAMS]
    Builds a jenkins job with parameters

    % yorktown jenkins -h
    Print help

    Options:
        -h                                show this message
        -j JOBNAME, --jobname JOBNAME     job to run
        -p PARAMS, --params PARAMS        job params as a json string
        -u USER, --user USER              username
        --pass PASSWORD                   password
