# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This module is part of nmeta Data Plane Auxiliary Engine (DPAE)
.
It is used to contain the Traffic Classification (TC) policy and provide
methods and direct variables to access it
.
Version 2.x Toulouse Code
"""

#*** Logging imports:
import logging
import logging.handlers
import coloredlogs

import sys

#*** YAML for config and policy file parsing:
import yaml

#*** Keys that must exist under 'identity' in the policy:
IDENTITY_KEYS = ('arp',
                 'lldp',
                 'dns',
                 'dhcp')

class TCPolicy(object):
    """
    This class is instantiated by nmeta2.py and provides methods
    to ingest the policy file main_policy.yaml and validate
    that it is correctly structured
    """
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('tc_policy_dpae_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('tc_policy_dpae_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
        _coloredlogs_enabled = _config.get_value('coloredlogs_enabled')
        _console_format = _config.get_value('console_format')
        #*** Set up Logging:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        #*** Syslog:
        if _syslog_enabled:
            #*** Log to syslog on host specified in config.yaml:
            self.syslog_handler = logging.handlers.SysLogHandler(address=(
                                                _loghost, _logport),
                                                facility=_logfacility)
            syslog_formatter = logging.Formatter(_syslog_format)
            self.syslog_handler.setFormatter(syslog_formatter)
            self.syslog_handler.setLevel(_logging_level_s)
            #*** Add syslog log handler to logger:
            self.logger.addHandler(self.syslog_handler)
        #*** Console logging:
        if _console_log_enabled:
            #*** Log to the console:
            if _coloredlogs_enabled:
                #*** Colourise the logs to make them easier to understand:
                coloredlogs.install(level=_logging_level_c,
                logger=self.logger, fmt=_console_format, datefmt='%H:%M:%S')
            else:
                #*** Add console log handler to logger:
                self.console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(_console_format)
                self.console_handler.setFormatter(console_formatter)
                self.console_handler.setLevel(_logging_level_c)
                self.logger.addHandler(self.console_handler)

        #*** Object to hold Controller main policies per interface in YAML:
        self.main_policy = dict()
        #*** Object to hold Controller optimised TC rules per iface in YAML:
        self.opt_rules = dict()

    def ingest_main_policy(self, main_policy_text, if_name):
        """
        Turn a plain text main policy file object into a YAML object
        and store it as a class variable
        """
        #*** Ingest the policy file:
        try:
            self.main_policy[if_name] = yaml.load(main_policy_text)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Failed to convert main policy to YAML "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        self.logger.debug("Successfully ingested main policy into YAML")
        return 1

    def ingest_optimised_rules(self, opt_rules_text, if_name):
        """
        Turn a plain optimised TC rules file object into a YAML object
        and store it as a class variable
        """
        #*** Ingest the policy file:
        try:
            self.opt_rules[if_name] = yaml.load(opt_rules_text)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Failed to convert optimised TC rules to YAML "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        self.logger.debug("Successfully ingested optimised TC rules into YAML")
        return 1

    def get_id_flag(self, if_name, id_key):
        """
        Get a value for an Identity Indicator harvesting flag
        """
        if not id_key in IDENTITY_KEYS:
            self.logger.error("The key %s is not valid", id_key)
            return 0
        return self.main_policy[if_name]['identity'][id_key]

    def get_tc_classifiers(self, if_name):
        """
        Return a list of traffic classifiers
        that should be run against ingress packets on a sniff interface.
        Each entry is a tuple of type (statistical or payload) and
        classifier name, example:
        [('statistical', 'statistical_qos_bandwidth_1')]
        """
        classifiers = []
        for idx, fe_match_list in enumerate(self.opt_rules[if_name]):
            self.logger.info("Optimised fe_match_list %s is %s", idx,
                                        fe_match_list)
            if not 'install_type' in fe_match_list:
                self.logger.error("no install_type key")
                continue
            if fe_match_list['install_type'] == 'to_dpae':
                self.logger.debug("Matched a DPAE TC condition...")
                classifiers.append((fe_match_list['type'],
                                            fe_match_list['value']))
        return classifiers
