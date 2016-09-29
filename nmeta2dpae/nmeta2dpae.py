#!/usr/bin/python

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
nmeta Data Plane Auxiliary Engine (DPAE)
Used as an auxilary data plane component for functions such as
offloading packet-intensive traffic classification
from the controller.
"""

import logging
import logging.handlers
import coloredlogs

import time

#*** For active mode packet sending:
from socket import socket, AF_PACKET, SOCK_RAW

#*** nmeta-dpae imports:
import config
import controlchannel
import tc_policy_dpae
import dp

#*** Multiprocessing:
import multiprocessing

class DPAE(object):
    """
    This class provides methods for a Data Plane Auxiliary Engine (DPAE),
    an auxiliary entity that provides services to nmeta.
    """
    def __init__(self):
        """
        Initialise the DPAE class
        """
        #*** Version number for compatibility checks:
        self.version = '0.3.5'

        #*** Instantiate config class which imports configuration file
        #*** config.yaml and provides access to keys/values:
        self.config = config.Config()

        #*** Get logging config values from config class:
        _logging_level_s = self.config.get_value \
                                    ('nmeta_dpae_logging_level_s')
        _logging_level_c = self.config.get_value \
                                    ('nmeta_dpae_logging_level_c')
        _syslog_enabled = self.config.get_value('syslog_enabled')
        _loghost = self.config.get_value('loghost')
        _logport = self.config.get_value('logport')
        _logfacility = self.config.get_value('logfacility')
        _syslog_format = self.config.get_value('syslog_format')
        _console_log_enabled = self.config.get_value('console_log_enabled')
        _coloredlogs_enabled = self.config.get_value('coloredlogs_enabled')
        _console_format = self.config.get_value('console_format')
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

        self.api_url = str(self.config.get_value('nmeta_controller_address'))
        self.api_port = str(self.config.get_value('nmeta_controller_port'))
        self.api_path = str(self.config.get_value('nmeta_api_path'))
        self.api_base = self.api_url + ':' + self.api_port + '/' + self.api_path
        print "api_base is", self.api_base

        #*** Interface(s) to receive TC packets on from switch:
        ifnames_raw = self.config.get_value('sniff_if_names')
        #*** if comma separated then perform a split:
        if ',' in ifnames_raw:
            self.if_names = ifnames_raw.split(',')
        else:
            self.if_names = list()
            self.if_names.append(ifnames_raw)

        #*** TBD, move to config:
        self.PHASE2_MAX_RETRIES = 3
        self.PHASE3_MAX_RETRIES = 3

        #*** Instantiate TC Policy class:
        self.tc_policy = tc_policy_dpae.TCPolicy(self.config)

        #*** Uncomment this for extra multiprocessing debug:
        #multiprocessing.log_to_stderr()
        #*** But if you're really stuck, run pylint on all .py files
        #***  looking for errors, as they won't show on console if they
        #***  occur in a child process...!!! They just manifest as program
        #***  halting unexpectedly with no screen output

    def per_interface(self, if_name):
        """
        Run per interface that sniffing will run on as separate process
        """
        #*** Instantiate Data Plane (DP) class:
        self.dp = dp.DP(self.config)

        #*** Instantiate Control Channel Class:
        self.controlchannel = controlchannel.ControlChannel(self, self.config,
                                    if_name, self.dp)

        finished = 0
        while not finished:
            #*** Start Phase 1 connection to the controller:
            phase1_connected = 0
            self.logger.info("Phase 1 initiated for interface=%s", if_name)
            while not phase1_connected:
                result = self.controlchannel.phase1(self.api_base, if_name)
                if not isinstance(result, dict):
                    self.logger.error("Phase 1 join to controller failed, "
                                        "will retry, "
                                    "interface=%s result=%s", if_name, result)
                    time.sleep(3)
                    phase1_connected = 0
                    continue

                if not 'dpae2ctrl_mac' in result:
                    self.logger.error("Phase 1 join to controller failed, "
                                        "will retry, "
                                    "interface=%s", if_name)
                    time.sleep(3)
                    phase1_connected = 0
                    continue
                else:
                    dpae2ctrl_mac = result['dpae2ctrl_mac']
                    ctrl2dpae_mac = result['ctrl2dpae_mac']
                    dpae_ethertype = result['dpae_ethertype']
                    location = result['location']
                    phase1_connected = 1
            self.logger.info("Phase 1 active for interface=%s", if_name)

            #*** Start Phase 2:
            phase2_connected = 0
            retries = 1
            while phase1_connected and not phase2_connected:
                self.logger.info("Phase 2 Negotiation interface=%s starting",
                        if_name)
                phase2_connected = self.controlchannel.phase2(location,
                                        if_name, dpae2ctrl_mac,
                                        ctrl2dpae_mac, dpae_ethertype)
                if phase2_connected:
                    self.logger.info("Phase 2 Active interface=%s",
                        if_name)
                else:
                    self.logger.info("Phase 2 retry number %s", retries)
                    time.sleep(3)
                    retries += 1
                    if retries > self.PHASE2_MAX_RETRIES:
                        self.logger.info("Phase 2 max retries exceeded, "
                                        "restarting at Phase 1")
                        phase1_connected = 0
            if not phase2_connected:
                continue

            #*** Start Phase 3:
            phase3_connected = 0
            retries = 1
            while phase1_connected and phase2_connected and not \
                                                    phase3_connected:
                self.logger.info("Phase 3 confirmation sniff starting"
                        "interface=%s", if_name)
                phase3_connected = self.controlchannel.phase3(location,
                                        if_name, dpae2ctrl_mac,
                                        ctrl2dpae_mac, dpae_ethertype)
                if phase3_connected:
                    self.logger.info("Phase 3 Active interface=%s",
                        if_name)
                else:
                    self.logger.info("Phase 3 retry number %s", retries)
                    time.sleep(3)
                    retries += 1
                    if retries > self.PHASE3_MAX_RETRIES:
                        self.logger.info("Phase 3 max retries exceeded, "
                                        "restarting at Phase 1")
                        phase1_connected = 0
                        phase2_connected = 0
            if not phase3_connected:
                continue

            #*** Start Phase 4:
            phase4_services = 0
            while phase1_connected and phase2_connected and phase3_connected \
                                            and not phase4_services:
                self.logger.info("Phase 4 services negotiation starting, "
                        "interface=%s", if_name)
                phase4_services = self.controlchannel.phase4(location,
                                        if_name)

            #*** Start Services:
            if 'traffic_classification' in phase4_services:
                self.logger.info("Phase 4 Traffic Classification service "
                                    "starting")
                self.cp_run(if_name, self.controlchannel, location)

    def cp_run(self, if_name, controlchannel, location):
        """
        Run Control Plane (CP) Traffic Classification for an interface
        """
        #*** Load main policy:
        location_policy = location + '/main_policy/'
        main_policy_yaml = 0
        while not main_policy_yaml:
            main_policy_yaml = controlchannel.get_policy(location_policy)
            time.sleep(1)
        self.logger.debug("Retrieved main_policy_yaml text %s",
                                                        main_policy_yaml)

        #*** Read the Controller main policy into the tc_policy class:
        if not self.tc_policy.ingest_main_policy(main_policy_yaml, if_name):
            self.logger.critical("Main policy ingestion failed")
            return 0

        #*** Load tc optimised rules:
        location_policy = location + '/services/tc/opt_rules/'
        tc_opt_rules_yaml = 0
        while not tc_opt_rules_yaml:
            tc_opt_rules_yaml = controlchannel.get_policy(location_policy)
        self.logger.debug("Retrieved tc_opt_rules_yaml text %s",
                                                        tc_opt_rules_yaml)

        #*** Read the optimised TC rules into the tc_policy class:
        if not self.tc_policy.ingest_optimised_rules(tc_opt_rules_yaml,
                                                                    if_name):
            self.logger.critical("TC optimised rules ingestion failed")
            return 0
        self.logger.debug("TC optimised rules are %s",
                                            self.tc_policy.opt_rules)

        #*** Start a Data Plane process:
        self.logger.info("Starting Data Plane process")
        interplane_queue = multiprocessing.Queue()
        sniff_ps = multiprocessing.Process(target=self.dp.dp_run,
                        args=(interplane_queue, self.tc_policy, if_name))
        sniff_ps.start()

        #*** Ask controlchannel to tell Controller to start sending
        #***  packets to us:
        self.logger.info("Tell Controller to start sending us packets")
        location_tc_state = location + '/services/tc/state/'
        tc_mode = ""
        while not tc_mode:
            self.logger.debug("Attempting to start TC with controller "
                                "for int=%s", if_name)
            tc_mode = controlchannel.tc_start(location_tc_state)
            if not tc_mode:
                #*** Setting state to run failed, retry after a bit...
                self.logger.error("Failed to start TC on Controller."
                                    "Will retry...")
                time.sleep(1)

        #*** Start keepalive child process to regularly check
        #***  that controller is alive and session is still valid:
        keepalive_ev = multiprocessing.Event()
        location_keepalive = location + '/keepalive/'
        keepalive_child = multiprocessing.Process(name='keepalive',
                                 target=controlchannel.keepalive,
                                 args=(keepalive_ev, location_keepalive,
                                 if_name))
        keepalive_child.start()

        #*** Read the queue for data plane events escalated to control plane
        #***  and check keepalive validity:
        finished = 0
        location_tc_classify = location + '/services/tc/classify/'
        while not finished:
            #*** Get result:
            if not interplane_queue.empty():
                tc_result = interplane_queue.get()
                if 'type' in tc_result:
                    if tc_result['type'] != 'none':
                        #*** Send via API to controller:
                        self.logger.debug("Sending result to controller: %s",
                                                            tc_result)
                        controlchannel.tc_advise_controller(
                                            location_tc_classify, tc_result)
            else:
                time.sleep(.01)
            #*** Check keepalive still valid:
            if keepalive_ev.is_set():
                self.logger.error("Detected flag for keepalive failed "
                        "interface=%s", if_name)
                #*** Do a complete restart of the connection to the controller:
                break

    def run(self):
        """
        Run the DPAE instance
        """
        #*** Start separate process for each interface
        #***  (effectively does a fork):
        self.logger.info("Starting individual processes per sniff interface")
        jobs = []
        for if_name in self.if_names:
            self.logger.info("Starting process for interface=%s",
                    if_name)
            p = multiprocessing.Process(target=self.per_interface,
                        args=(if_name,))
            jobs.append(p)
            p.start()
            time.sleep(1)

if __name__ == '__main__':
    #*** Instantiate the DPAE class:
    dpae = DPAE()
    #*** Start the DPAE:
    dpae.run()
