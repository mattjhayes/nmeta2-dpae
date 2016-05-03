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
It provides an object for traffic classification
and includes ingesting the policy from YAML and checking
packets against policy, calling appropriate classifiers
and returning actions.
.
Version 2.x Toulouse Code
"""

#*** Logging imports:
import logging
import logging.handlers
import coloredlogs

#*** General imports:
import socket
import sys
import struct

#*** Import dpkt for packet parsing:
import dpkt

#*** To represent TCP flows and their context:
import flow

#*** For importing custom classifiers:
import importlib

class TC(object):
    """
    This class is instantiated by nmeta2_dpae.py and provides methods
    to ingest the policy as yaml and check
    packets against policy, calling appropriate classifiers
    and returning actions.
    """
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('tc_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('tc_logging_level_c')
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

        #*** Initialise Identity Harvest flags (they get set at DPAE join time)
        self.id_arp = 0
        self.id_lldp = 0
        self.id_dns = 0
        self.id_dhcp = 0
        #*** Initialise list for TC classifiers to run:
        self.classifiers = []

        #*** Retrieve config values for elephant flow suppression:
        self.suppress_flow_pkt_count_initial = \
                           _config.get_value("suppress_flow_pkt_count_initial")
        self.suppress_flow_pkt_count_backoff = \
                           _config.get_value("suppress_flow_pkt_count_backoff")

        #*** Retrieve config values for flow class db connection to use:
        _mongo_addr = _config.get_value("mongo_addr")
        _mongo_port = _config.get_value("mongo_port")
        #*** Instantiate a flow object for classifiers to work with:
        self.flow = flow.Flow(self.logger, _mongo_addr, _mongo_port)

    def instantiate_classifiers(self, _classifiers):
        """
        Dynamically import and instantiate classes for any
        dynamic classifiers specified in the controller
        nmeta2 main_policy.yaml
        .
        Passed a list of tuples of classifier type / classifer name
        .
        Classifier modules live in the 'classifiers' subdirectory
        .
        """
        self.logger.debug("Loading dynamic classifiers into TC module")

        for tc_type, module_name in _classifiers:
            #*** Dynamically import and instantiate class from classifiers dir:
            self.logger.debug("Importing module type=%s module_name=%s",
                                        tc_type, "classifiers." + module_name)
            try:
                module = importlib.import_module("classifiers." + module_name)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("Failed to dynamically load classifier "
                                    "module %s from classifiers subdirectory."
                                    "Please check that module exists and alter"
                                    " main_policy configuration in controller "
                                    "nmeta2 configuration if required",
                                    module_name)
                self.logger.error("Exception is %s, %s, %s",
                                            exc_type, exc_value, exc_traceback)
                sys.exit("Exiting, please fix error...")

            #*** Dynamically instantiate class 'Classifier':
            self.logger.debug("Instantiating module class")
            class_ = getattr(module, 'Classifier')
            self.classifiers.append(class_(self.logger))

    # UNDER CONSTRUCTION...
    def try_except(fn):
        def wrapped(*args, **kwargs):
            self.logger.debug("Trying...")
            try:
                return fn(*args, **kwargs)
            except Exception, e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("Exception %s, %s, %s",
                        exc_type, exc_value, exc_traceback)
                
        return wrapped

    def classify_dpkt_wrapper(self, pkt, pkt_receive_timestamp, if_name):
        """
        Used to catch and handle exceptions in classify_dpkt otherwise
        it can just hang with no explaination...
        """
        try:
            result = self.classify_dpkt(pkt, pkt_receive_timestamp, if_name)
            return result
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("classify_dpkt exception %s, %s, %s",
                                            exc_type, exc_value, exc_traceback)
            return {}

    @try_except
    def classify_dpkt(self, pkt, pkt_receive_timestamp, if_name):
        """
        Perform traffic classification on a packet
        using dpkt for packet parsing
        """
        result = {'type': 'none', 'subtype': 'none', 'actions': 0}
        ip = 0
        udp = 0
        tcp = 0
        #*** Read into dpkt:
        eth = dpkt.ethernet.Ethernet(pkt)
        #*** Set local variables for efficient access, speed is critical...
        eth_src = mac_addr(eth.src)
        eth_dst = mac_addr(eth.dst)
        eth_type = eth.type

        if eth_type == 2048:
            ip = eth.data
            ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
            ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)
            #*** Check if UDP or TCP:
            if ip.p == 6:
                tcp = ip.data
                tcp_src = tcp.sport
                tcp_dst = tcp.dport

            elif ip.p == 17:
                udp = ip.data
                udp_src = udp.sport
                udp_dst = udp.dport

        #*** Check for Identity Indicators:
        if udp:
            if udp_src == 53 or udp_dst == 53:
                #*** DNS (UDP):
                return self._parse_dns(udp.data, eth_src)

            elif udp_src == 67 or udp_dst == 67:
                #*** DHCP:
                return self._parse_dhcp(udp.data, eth_src)

        if tcp:
            if tcp_src == 53 or tcp_dst == 53:
                #*** DNS (TCP):
                return self._parse_dns(tcp.data, eth_src)

        if eth_type == 35020:
            #*** LLDP:
            return self._parse_lldp(pkt, eth_src)

        if eth_type == 2054:
            #*** ARP:
            return self._parse_arp(eth, eth_src)

        #*** TEMP EXCEPTION FOR TESTING:
        foo = 10 * (1/0)

        #*** The following is TCP specific but shouldn't be... TBD...
        if tcp:
            #*** Read packet into flow object for classifiers to work with:
            self.flow.ingest_packet(pkt, pkt_receive_timestamp)

            #*** Run any custom classifiers:
            for classifier in self.classifiers:
                try:
                    result_classifier = classifier.classifier(self.flow)
                except:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.logger.error("Exception in custom classifier %s."
                                    "Exception %s, %s, %s",
                                classifier, exc_type, exc_value, exc_traceback)
                    return result

            #*** TBD, this will need updating for more types of return actions:
            if 'qos_treatment' in result_classifier:
                result['qos_treatment'] = result_classifier['qos_treatment']
                result['actions'] = 1
                result['type'] = 'treatment'

        #*** Suppress Elephant flows:
        #***  TBD, do on more than just IPv4 TCP...:
        if tcp and self.flow.packet_count >= \
                                self.suppress_flow_pkt_count_initial:
            #*** Only suppress if there's been sufficient backoff since
            #***  any previous suppressions to prevent overload of ctrlr
            if not self.flow.suppressed or (self.flow.packet_count > \
                            (self.flow.suppressed + \
                            self.suppress_flow_pkt_count_backoff)):
                #*** Update the suppress counter on the flow:
                self.flow.set_suppress_flow()
                self.logger.debug("Suppressing TCP stream src_ip=%s "
                                    "src_port=%s dst_ip=%s dst_port=%s",
                                    self.flow.ip_src,
                                    self.flow.tcp_src,
                                    self.flow.ip_dst,
                                    self.flow.tcp_dst)
                if result['type'] == 'none':
                    result['type'] = 'suppress'
                elif result['type'] == 'treatment':
                    result['type'] = 'treatment+suppress'
                else:
                    self.logger.error("Unknown result type %s", result['type'])

        if result['type'] != 'none':
            #*** Add context to result:
            result['ip_A'] = self.flow.ip_src
            result['ip_B'] = self.flow.ip_dst
            result['proto'] = 'tcp'
            result['tp_A'] = self.flow.tcp_src
            result['tp_B'] = self.flow.tcp_dst
            result['flow_packets'] = self.flow.packet_count

        return result

    def _parse_dns(self, dns_data, eth_src):
        """
        Check if packet is DNS, and if so return a list
        of answers (if exist), with each list item a dict
        of type/name/address/ttl
        """
        if self.id_dns:
            #*** DNS:
            self.logger.debug("Is it DNS?")
            dns = dpkt.dns.DNS(dns_data)
            queries = dns.qd
            answers = dns.an
            detail1 = []
            for answer in answers:
                if answer.type == 1:
                    #*** DNS A Record:
                    answer_ip = socket.inet_ntoa(answer.rdata)
                    answer_name = answer.name
                    answer_ttl = answer.ttl
                    self.logger.debug("dns_answer_name=%s dns_answer_A=%s "
                                "answer_ttl=%s",
                                answer_name, answer_ip, answer_ttl)
                    record = {'type': 'A',
                                'name': answer_name,
                                'address': answer_ip,
                                'ttl': answer_ttl}
                    detail1.append(record)
                elif answer.type == 5:
                    #*** DNS CNAME Record:
                    answer_cname = answer.cname
                    answer_name = answer.name
                    self.logger.debug("dns_answer_name=%s dns_answer_CNAME=%s",
                                "answer_ttl=%s",
                                answer_name, answer_cname, answer_ttl)
                    record = {'type': 'CNAME',
                                'name': answer_name,
                                'address': answer_cname,
                                'ttl': answer_ttl}
                    detail1.append(record)
                else:
                    #*** Not a type that we handle yet
                    pass
            if len(detail1) > 0:
                result = {'type': 'id', 'subtype': 'dns', 'src_mac': eth_src,
                                                'detail1': detail1}
            else:
                result = 0
            self.logger.debug("DNS result=%s", result)
            return result
        else:
            return 0

    def _parse_dhcp(self, udp_data, eth_src):
        """
        Check if packet is DHCP, and if so return the details
        """
        dhcp = dpkt.dhcp.DHCP(udp_data)
        if self.id_dhcp and dhcp:
            #*** DHCP:
            self.logger.debug("DHCP details are %s", dhcp)
            result = {'type': 'id', 'subtype': 'dhcp', 'src_mac': eth_src,
                                                'detail1': dhcp}
            return result
        else:
            return 0

    def _parse_arp(self, eth, eth_src):
        """
        Check if packet is ARP, and if so return the details
        """
        if self.id_arp:
            #*** ARP:
            self.logger.debug("Is it ARP?")
            arp = eth.arp
            if arp:
                #*** Build a CSV string of spa,sha,tpa,tha:
                arp_details = socket.inet_ntoa(arp.spa)
                arp_details += "," + mac_addr(arp.sha)
                arp_details += "," + socket.inet_ntoa(arp.tpa)
                arp_details += "," + mac_addr(arp.sha)
                self.logger.debug("ARP details are %s", arp_details)
                result = {'type': 'id', 'subtype': 'arp',
                                    'src_mac': eth_src,
                                    'detail1': arp_details}
                return result
            else:
                return 0
        else:
            return 0

    def _parse_lldp(self, pkt, eth_src):
        """
        Check if packet is LLDP, and if so return the details
        """
        if self.id_lldp:
            #*** LLDP?, try a decode:
            self.logger.debug("Is it LLDP?")
            payload = pkt[14:]
            system_name, port_id = self._parse_lldp_detail(payload)
            self.logger.debug("LLDP MAC=%s system_name=%s port_id=%s",
                                    eth_src, system_name, port_id)
            result = {'type': 'id', 'subtype': 'lldp',
                                    'src_mac': eth_src,
                                    'detail1': system_name}
            return result
        else:
            return 0

    def _parse_lldp_detail(self, lldpPayload):
        """
        Parse basic LLDP parameters from an LLDP packet payload.
        Based on github code by GoozeyX
        (https://raw.githubusercontent.com/GoozeyX/python_lldp/master/ \
                     lldp_collector.py)
        """
        system_name = None
        vlan_id = None
        port_id = None

        while lldpPayload:
            tlv_header = struct.unpack("!H", lldpPayload[:2])[0]
            tlv_type = tlv_header >> 9
            tlv_len = (tlv_header & 0x01ff)
            lldpDU = lldpPayload[2:tlv_len + 2]
            if tlv_type == 127:
                tlv_oui = lldpDU[:3]
                tlv_subtype = lldpDU[3:4]
                tlv_datafield = lldpDU[4:tlv_len]
                if tlv_oui == "\x00\x80\xC2" and tlv_subtype == "\x01":
                    vlan_id = struct.unpack("!H", tlv_datafield)[0]

            elif tlv_type == 0:
                # TLV Type is ZERO, Breaking the while loop:
                break
            else:
                tlv_subtype = struct.unpack("!B", lldpDU[0:1]) \
                                                    if tlv_type is 2 else ""
                startbyte = 1 if tlv_type is 2 else 0
                tlv_datafield = lldpDU[startbyte:tlv_len]

            if tlv_type == 4:
                port_id = tlv_datafield
            elif tlv_type == 5:
                system_name = tlv_datafield
            else:
                pass

            lldpPayload = lldpPayload[2 + tlv_len:]

        return (system_name, port_id)

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
