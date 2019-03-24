#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""
centralized logging module
import throughout your application by using
# import logging
# logger = logging.getLogger(__name__)
# logger.debug("test")
# logger.info("test")
# logger.warning("test")
# logger.error("test")
# logger.exception("test")
"""

import logging
import logging.config
from .utils import AnsiColor as color

class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances.keys():
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class LoggerManager(object):
    __metaclass__ = Singleton

    _loggers = {}

    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def getLogger(name=None):
        format=('{blue1}%(asctime)s '
                '{red1}%(filename)s:%(lineno)d '
                '{yel1}%(levelname)s '
                '{gre1}%(funcName)s '
                '{res}%(message)s').format(blue1=color.blue, red1=color.red, yel1=color.yellow, res=color.end, gre1=color.magenta)
        if not name:
            logging.basicConfig(format=format)
            return logging.getLogger()
        elif name not in LoggerManager._loggers.keys():
            logging.basicConfig(format=format)
            LoggerManager._loggers[name] = logging.getLogger(str(name))
        return LoggerManager._loggers[name]

log=LoggerManager().getLogger("dxmini")
log.setLevel(level=logging.DEBUG)
