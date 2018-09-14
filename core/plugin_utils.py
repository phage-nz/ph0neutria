#!/usr/bin/python3

from .config_utils import get_base_config
from .log_utils import get_module_logger

import importlib
import os
import re
import sys


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


def load_plugins():
    """Load all modules in the 'plugins' subdirectory.

    Returns:
    - modules: (type: Module list) list of modules.
    """
    try:
        pysearchre = re.compile('.py$', re.IGNORECASE)

        pluginfiles = filter(pysearchre.search, os.listdir(os.path.join(os.path.dirname(__file__), 'plugins')))

        form_module = lambda fp: '.' + os.path.splitext(fp)[0]
        plugins = map(form_module, pluginfiles)
        importlib.import_module('core.plugins')
        modules = []

        for plugin in plugins:
                 if not plugin.startswith('.__'):
                     modules.append(importlib.import_module(plugin, package='core.plugins'))

        return modules

    except Exception as e:
        LOGGING.error('Problem loading plugins. Terminating core application.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    sys.exit(1)

