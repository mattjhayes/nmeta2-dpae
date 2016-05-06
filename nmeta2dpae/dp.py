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

#*** nmeta - Network Metadata - Policy Interpretation Class and Methods

"""
This module is part of the nmeta2 suite
.
It provides an object for data plane coordination services
.
Version 2.x Toulouse Code
"""

#*** Logging imports:
import logging
import logging.handlers
import coloredlogs

#*** General imports:
import sys
import traceback

#*** JSON:
import json
from json import JSONEncoder

#*** nmeta-dpae imports:
import tc
import sniff

class DP(object):
    """
    This class is instantiated by nmeta2_dpae.py and provides methods
    to run the data plane services.
    """
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('dp_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('dp_logging_level_c')
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

        #*** Instantiate Sniff Class:
        self.sniff = sniff.Sniff(_config)

        #*** Instantiate TC Classification class:
        self.tc = tc.TC(_config)

    def dp_discover(self, queue, if_name, dpae2ctrl_mac,
                        ctrl2dpae_mac, dpae_ethertype, timeout, uuid_dpae,
                        uuid_controller):
        """
        Data plane service for DPAE Join Discover Packet Sniffing
        """
        self.logger.debug("Starting data plane discover confirm on %s",
                                                            if_name)
        #*** Run the sniffer to see if we can capture a discover
        #***  confirm packet:
        try:
            payload = self.sniff.discover_confirm(if_name, dpae2ctrl_mac,
                                        ctrl2dpae_mac, dpae_ethertype, timeout)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("sniff.discover_confirm exception %s, %s, %s",
                                            exc_type, exc_value, exc_traceback)
            result = 0
            queue.put(result)
            return result

        if payload:
            #*** Validate JSON in payload:
            json_decode = JSON_Body(str(payload))
            if json_decode.error:
                self.logger.error("Phase 3 packet payload is not JSON"
                                            "error=%s", json_decode.error_full)
                result = 0
                queue.put(result)
                return result
            #*** Validate required keys are present in the JSON:
            if not json_decode.validate(['hostname_dpae', 'uuid_dpae',
                                                'uuid_controller', 'if_name']):
                self.logger.error("Validation error %s", json_decode.error)
                result = 0
                queue.put(result)
                return result

            #*** Validate the Controller UUID value in the JSON:
            if str(json_decode['uuid_controller']) == str(uuid_controller):
                self.logger.info("Success! Matched discover confirm.")
                result = 1
                queue.put(result)
                return result
            else:
                self.logger.error("Validation error for uuid_controller")
                result = 0
                queue.put(result)
                return result
        else:
            self.logger.warning("No payload returned. This happens sometimes")
            result = 0
            queue.put(result)
            return result

    def dp_run(self, interplane_queue, tc_policy, if_name):
        """
        Run Data Plane (DP) Traffic Classification for an interface
        """
        tc_mode = 'passive'

        #*** Set local identity harvest flags in tc for efficient access:
        self.logger.debug("Setting Identity Harvest Flags")
        self.tc.id_arp = tc_policy.get_id_flag(if_name, 'arp')
        self.tc.id_lldp = tc_policy.get_id_flag(if_name, 'lldp')
        self.tc.id_dns = tc_policy.get_id_flag(if_name, 'dns')
        self.tc.id_dhcp = tc_policy.get_id_flag(if_name, 'dhcp')

        #*** Set up TC classifiers to run in tc class:
        _classifiers = tc_policy.get_tc_classifiers(if_name)
        self.tc.instantiate_classifiers(_classifiers)

        #*** Wait to be advised of TC Mode:
        # TBD

        #*** Run sniffer to capture traffic and send to TC:
        try:
            self.sniff.sniff_run(if_name, self.tc, interplane_queue)
        except Exception, e:
            self.logger.critical("sniff.sniff_run: %s", e, exc_info=True)
            return 0

        #*** For active mode:
        #if tc_mode == 'active':
        #    send_socket = socket(AF_PACKET, SOCK_RAW)
        #    send_socket.bind((if_name, 0))

        #if tc_mode == 'active':
            #*** Active Mode: send the packet back to the switch:
        #    send_socket.send(pkt)

class JSON_Body(object):
    """
    Represents a JSON-encoded body of an HTTP request.
    Doesn't do logging, but does set .error when things
    don't go to plan with a friendly message.
    """
    def __init__(self, req_body):
        self.json = {}
        self.error = ""
        self.error_full = ""
        self.req_body = self.decode(req_body)

    def decode(self, req_body):
        """
        Passed an allegedly JSON body and see if it
        decodes. Set error variable for exceptions
        """
        json_decode = {}
        if req_body:
            #*** Try decode as JSON:
            try:
                json_decode = json.loads(req_body)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.error = '{\"Error\": \"Bad JSON\"}'
                self.error_full = '{\"Error\": \"Bad JSON\",' + \
                             '\"exc_type\":' + str(exc_type) + ',' + \
                             '\"exc_value\":' + str(exc_value) + ',' + \
                             '\"exc_traceback\":' + str(exc_traceback) + '}'
                return 0
        else:
            json_decode = {}
        self.json = json_decode
        return json_decode

    def validate(self, key_list):
        """
        Passed a list of keys and check that they exist in the
        JSON. If they don't return 0 and set error to description
        of first missing key that was found
        """
        for key in key_list:
            if not key in self.req_body:
                self.error = '{\"Error\": \"No ' + key + '\"}'
                return 0
        return 1

    def __getitem__(self, key):
        """
        Passed a key and see if it exists in JSON
        object. If it does, return the value for the key.
        If not, return 0
        Example:
            foo = json_body['foo']
        """
        if key in self.req_body:
            return self.req_body[key]
        else:
            return 0
