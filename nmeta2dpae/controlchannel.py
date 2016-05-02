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
This module is part of the nmeta2 suite
.
It is provides control channel services between the nmeta
Data Plane Auxiliary Engine (DPAE) and the OpenFlow controller
using REST API calls
"""

#*** Logging imports:
import logging
import logging.handlers
import coloredlogs

#*** General imports:
import socket, sys
import re
import time

#*** Import library to do HTTP GET requests:
import requests

#*** JSON for API calls:
import json
from json import JSONEncoder

#*** Universal Unique Identifier:
import uuid
from uuid import UUID

#*** Scapy for sending/receiving packets:
from scapy.all import Raw, Ether, sendp

#*** Multiprocessing:
import multiprocessing

class ControlChannel(object):
    """
    This class is instantiated by nmeta_dpae.py and provides methods to
    interact with the nmeta control plane
    """
    def __init__(self, _nmeta, _config, if_name, sniff):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('controlplane_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('controlplane_logging_level_c')
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
                logger=self.logger, fmt=_console_format)
            else:
                #*** Add console log handler to logger:
                self.console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(_console_format)
                self.console_handler.setFormatter(console_formatter)
                self.console_handler.setLevel(_logging_level_c)
                self.logger.addHandler(self.console_handler)

        #*** Set Python requests and urllib3 module logging levels:
        _logging_level_requests = _config.get_value \
                                    ('requests_logging_level')
        logging.getLogger("requests").setLevel(_logging_level_requests)
        logging.getLogger("urllib3").setLevel(_logging_level_requests)

        #*** Update JSON to support UUID encoding:
        JSONEncoder_olddefault = JSONEncoder.default
        def JSONEncoder_newdefault(self, o):
            """
            Update JSON to support UUID encoding
            """
            if isinstance(o, UUID):
                return str(o)
            return JSONEncoder_olddefault(self, o)
        JSONEncoder.default = JSONEncoder_newdefault
        self.config = _config
        self._nmeta = _nmeta
        self.sniff = sniff

        self.keepalive_interval = \
                        float(self.config.get_value('keepalive_interval'))
        self.keepalive_retries = \
                        int(self.config.get_value('keepalive_retries'))

    def phase1(self, api_base, if_name):
        """
        Phase 1 (global to DPAE) connection to the control plane,
        as an active data plane auxiliary device
        """
        self.logger.info("Phase 1 Disconnected")
        #*** Connect to controller via API:
        #*** Set up an HTTP/1.1 session:
        self.s = requests.Session()
        headers = {'Connection': 'keep-alive',
                   'Cache-Control': 'no-cache',
                   'Pragma': 'no-cache'}
        #*** Create a new DPAE resource on the controller
        #*** Pass our hostname and UUID:
        self.hostname = socket.getfqdn()
        self.our_uuid = uuid.uuid1()
        json_create_dpae = json.dumps({'hostname_dpae': self.hostname,
                                        'if_name': if_name,
                                        'uuid_dpae': self.our_uuid})
        try:
            r = self.s.post(api_base, headers=headers, data=json_create_dpae)

        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Phase 1 exception while posting join to "
                            "controller, "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            self.logger.info("    Is the controller app running???")
            return 0
        self.logger.info("Phase 1 Connect")
        if not r.status_code == 201:
            self.logger.error("Phase 1 error connecting to controller, return "
                                "status=%s",
                                r.status_code)
            return 0

        #*** Decode API response as JSON:
        api_response = JSON_Body(r.json())
        if api_response.error:
            return ({'status': 400, 'msg': api_response.error})
        self.logger.debug("Phase 1 response body=%s",
                                    api_response.json)
        #*** Validate required keys are present in JSON:
        if not api_response.validate(['hostname_controller', 'uuid_dpae',
                                        'uuid_controller', 'dpae2ctrl_mac',
                                        'ctrl2dpae_mac', 'dpae_ethertype']):
            self.logger.error("Validation error %s", api_response.error)
            return ({'status': 400, 'msg': api_response.error})

        uuid_dpae_response = api_response['uuid_dpae']
        if str(uuid_dpae_response) != str(self.our_uuid):
            self.logger.error("Phase 1 response uuid_dpae mismatch")
            return 0

        self.uuid_controller = api_response['uuid_controller']

        #*** MAC address for DPAE to Controller:
        dpae2ctrl_mac = api_response['dpae2ctrl_mac']
        if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                            dpae2ctrl_mac.lower()):
            self.logger.error("Phase 1 invalid dpae2ctrl_mac, mac=%s",
                                    dpae2ctrl_mac)
            return 0

        #*** MAC address for Controller to DPAE:
        ctrl2dpae_mac = api_response['ctrl2dpae_mac']
        if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                            ctrl2dpae_mac.lower()):
            self.logger.error("Phase 1 invalid ctrl2dpae_mac, mac=%s",
                                    ctrl2dpae_mac)
            return 0

        #*** Ethertype for packets between DPAE and Controller:
        dpae_ethertype = int(api_response['dpae_ethertype'])

        #*** Note: Requests module doesn't auto redirect for a status 201 so
        #***  need to manually pull out resource location from the headers:
        result = {'dpae2ctrl_mac': dpae2ctrl_mac,
                'ctrl2dpae_mac': ctrl2dpae_mac,
                'dpae_ethertype': dpae_ethertype,
                'location': r.headers['location']}

        #*** Yay, we've successfully completed phase 1
        self.logger.info("Phase 1 Active")

        return result

    def phase2(self, api_base, if_name, dpae2ctrl_mac, ctrl2dpae_mac,
                        dpae_ethertype):
        """
        Phase 2 (per DPAE sniffing interface)
        switch/port discovery
        """
        #*** Send packet with scapy:
        json_pkt_data = json.dumps({'hostname_dpae': self.hostname,
                                    'if_name': if_name,
                                    'uuid_dpae': self.our_uuid,
                                    'uuid_controller': self.uuid_controller})
        #*** Create packet to registration MAC containing our JSON data:
        reg_pkt = Ether(src=ctrl2dpae_mac, dst=dpae2ctrl_mac, \
                        type=dpae_ethertype) / Raw(load=json_pkt_data)
        #*** Send packet:
        try:
            sendp(reg_pkt, iface=if_name)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Phase 2 exception while sending discovery "
                            "packet, "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        #*** Wait for a small amount of time:
        time.sleep(1)

        #*** Check that the controller has updated the resource with
        #***  switch/port details:
        json_query_dpae = json.dumps({'hostname_dpae': self.hostname,
                                    'if_name': if_name,
                                    'uuid_dpae': self.our_uuid,
                                    'uuid_controller': self.uuid_controller})
        try:
            r = self.s.get(api_base, data=json_query_dpae)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Phase 2 exception while retrieving from"
                            " controller, "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0

        #*** Decode API response as JSON:
        api_response = JSON_Body(r.json())
        if api_response.error:
            return ({'status': 400, 'msg': api_response.error})
        self.logger.debug("Phase 2 GET response=%s", api_response.json)
        #*** Validate required keys are present in JSON:
        if not api_response.validate(['hostname_dpae', 'uuid_dpae',
                                        'dpid', 'switch_port']):
            self.logger.error("Validation error %s", api_response.error)
            return ({'status': 400, 'msg': api_response.error})
        #*** Check has our UUID correct:
        uuid_dpae_response = api_response['uuid_dpae']
        if str(uuid_dpae_response) != str(self.our_uuid):
            self.logger.error("Phase 2 response uuid_dpae mismatch")
            return 0
        #*** Success:
        return 1

    def phase3(self, api_base, if_name, dpae2ctrl_mac, ctrl2dpae_mac,
                        dpae_ethertype):
        """
        Phase 3 (per DPAE sniffing interface)
        confirmation of sniffing packets
        """
        result = 0
        #*** Max time in seconds to wait for sniff process:
        sniff_wait_time = 12
        sniff_timeout = 20
        sniff_timeout_ps = 10

        #*** Start sniffer process:
        self.logger.info("Starting separate sniff process")
        queue = multiprocessing.Queue()
        sniff_ps = multiprocessing.Process(target=self.sniff.discover_confirm,
                        args=(queue, if_name, dpae2ctrl_mac, ctrl2dpae_mac,
                        dpae_ethertype, sniff_timeout_ps, self.our_uuid,
                        self.uuid_controller))
        sniff_ps.start()

        #*** Instruct controller to send confirmation packet:
        url_send_conf_pkt = api_base + '/send_conf_packet/'
        
        json_send_conf_pkt = json.dumps({'hostname_dpae': self.hostname,
                                    'if_name': if_name,
                                    'uuid_dpae': self.our_uuid,
                                    'uuid_controller': self.uuid_controller})
        try:
            r = self.s.post(url_send_conf_pkt, data=json_send_conf_pkt)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Phase 3 exception while requesting controller "
                            "to send a sniff confirmation packet, "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0

        #*** Wait for a small amount of time:
        time.sleep(sniff_wait_time)

        #*** Get result:
        if not queue.empty():
            self.logger.debug("Reading queue from child sniff process...")
            result = queue.get()
            self.logger.debug("Phase 3 result of sniff confirmation is %s",
                                    result)
        else:
            self.logger.debug("Queue from child sniff process was empty")

        #*** Close the child sniff process down:
        queue.close()
        queue.join_thread()
        sniff_ps.join(sniff_timeout)

        #if sniff_ps.exitcode != 0:
           # self.logger.warning("Phase 3 exception from sniff process "
           #                     "exitcode=%s", sniff_ps.exitcode)
            #return 0

        return result

    def phase4(self, api_base, if_name):
        """
        Phase 4 (per DPAE sniffing interface)
        Negotiate what services will be run by the DPAE
        """
        #*** This is TBD, for the moment Traffic Classification is
        #***  the only service so no negotiation is done
        services = {'traffic_classification': 1}
        return services

    def get_policy(self, location):
        """
        Get the a policy from
        the Controller (YAML in string format)
        """
        try:
            r = self.s.get(location)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Exception while retrieving policy from"
                            " controller location=%s, "
                            "%s, %s, %s", location,
                            exc_type, exc_value, exc_traceback)
            return 0
        return r.text

    def tc_start(self, location):
        """
        Tell the Controller to start sending us packets that
        need traffic classification
        """
        self.logger.debug("Sending API call to Controller to start TC")
        json_start_tc = json.dumps({'tc_state': 'run',
                                    'dpae_version': self._nmeta.version,
                                    'hostname_dpae': self.hostname,
                                    'uuid_dpae': self.our_uuid,
                                    'uuid_controller': self.uuid_controller})
        try:
            r = self.s.put(location, data=json_start_tc)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Exception while setting TC to run on"
                            " controller, %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        if r.status_code != 200:
            self.logger.error("Unexpected response from controller status=%s "
                        "response=%s", r.status_code, r.text)
            return 0

        #*** Decode API response as JSON:
        api_response = JSON_Body(r.json())

        if api_response.error:
            self.logger.error("Bad JSON response for tc_start error=%s",
                                api_response.error)
            return 0

        self.logger.debug("tc_start response body=%s", api_response.json)

        #*** Validate required keys are present in JSON:
        if not api_response.validate(['uuid_dpae', 'status', 'mode']):
            self.logger.error("Validation error %s", api_response.error)
            return 0
        #*** Check has our UUID correct:
        uuid_dpae_response = api_response['uuid_dpae']
        if str(uuid_dpae_response) != str(self.our_uuid):
            self.logger.error("tc_start response uuid_dpae mismatch")
            return 0

        #*** Success:
        return api_response['mode']

    def tc_advise_controller(self, location, tc_result):
        """
        Pass Traffic Classification (TC) information to
        the controller via the API
        """
        self.logger.debug("Sending TC result via API call to Controller")
        try:
            json_tc_advice = json.dumps(tc_result)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Exception encoding TC result into JSON,"
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        try:
            r = self.s.post(location, data=json_tc_advice)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Exception while sending TC advice to"
                            " controller, %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        if r.status_code != 200:
            return 0
        return 1

    def keepalive(self, event_flag, location, if_name):
        """
        Do regular keepalive polls to the DPAE to check
        if is still available, in dedicated process.
        If keepalive fails, then set an event flag
        for parent process.
        """
        #*** TBD, use config for values and require multiple failures before marking as down
        failed_test = 0
        failed_concurrent = 0
        failed_total = 0
        count = 0
        self.logger.info("Child keepalive started...")
        keepalive_data = json.dumps({'keepalive': 1,
                                    'if_name': if_name,
                                    'uuid_dpae': self.our_uuid,
                                    'uuid_controller': self.uuid_controller})
        while not failed_total:
            while not failed_test:
                try:
                    r = self.s.put(location, data=keepalive_data)
                except:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.logger.error("Exception while sending keepalive to"
                            " controller, %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                    failed_test = 1
                    time.sleep(self.keepalive_interval)
                    break
                if r.status_code == 200:
                    #*** Had a successful keepalive test so reset concurrent
                    #***  failures to 0:
                    failed_concurrent = 0
                else:
                    failed_test = 1
                    self.logger.info("Failed keepalive to controller, "
                                        "http_code=%s text=%s",
                                        r.status_code, r.text)
                    time.sleep(self.keepalive_interval)
                    break
                time.sleep(self.keepalive_interval)
            #*** failed a test so increment concurrent failure counter:
            failed_concurrent += 1
            self.logger.info("Keepalive failure, retries=%s",
                                    failed_concurrent)
            if failed_concurrent >= self.keepalive_retries:
                failed_total = 1
            else:
                #*** reset failed_test so that we keep testing:
                failed_test = 0
        event_flag.set()
        self.logger.error("=========== Keepalive failed ===========")
        return

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
