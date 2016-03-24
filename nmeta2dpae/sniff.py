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
It provides packet sniffing services
"""

import socket

import struct

import time
import sys

#*** Import dpkt for packet parsing:
import dpkt

import logging
import logging.handlers

#*** JSON:
import json
from json import JSONEncoder

#*** For setting Ethernet interface promiscuous mode:
import ctypes
import fcntl

#*** Constants for setting Ethernet interface promiscuous mode:
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

#*** TBD, this should be autodetected:
MTU = 1500

#*** TBD, this should be validated:
ETH_P_ALL = 3

class Sniff(object):
    """
    This class is instantiated by nmeta_dpae.py and provides methods to
    sniff and process inbound packets on a given interface
    """
    def __init__(self, _nmeta, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('sniff_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('sniff_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
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
            self.console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(_console_format)
            self.console_handler.setFormatter(console_formatter)
            self.console_handler.setLevel(_logging_level_c)
            #*** Add console log handler to logger:
            self.logger.addHandler(self.console_handler)
        #*** Update JSON to support UUID encoding:
        JSONEncoder_olddefault = JSONEncoder.default
        def JSONEncoder_newdefault(self, o):
            if isinstance(o, UUID):
                return str(o)
            return JSONEncoder_olddefault(self, o)
        JSONEncoder.default = JSONEncoder_newdefault
        
    def tc_sniff(self, queue, if_name):
        """
        This function processes sniffed packets
        """
        #*** Start layer 2 socket for packet sniffing:
        self.logger.info("Starting socket sniff connection to interface=%s",
                            if_name)
        mysock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        mysock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        mysock.bind((if_name, ETH_P_ALL))
        self.set_promiscuous_mode(if_name, mysock)

        finished = 0
        while not finished:
            #*** Get packet from socket:
            pkt, sa_ll = mysock.recvfrom(MTU)
            #*** Ignore outgoing packets:
            pkt_type = sa_ll[2]
            
            if pkt_type == socket.PACKET_OUTGOING:
                continue

            #*** Record the time (would be better if was actual receive time)
            pkt_receive_timestamp = time.time()
            pkt_tuple = (pkt, pkt_receive_timestamp)

            #*** Send result in queue back to the parent process:
            queue.put(pkt_tuple)

    def discover_confirm(self, queue, if_name, dpae2ctrl_mac, ctrl2dpae_mac,
                        dpae_ethertype, timeout, uuid_dpae, uuid_controller):
        """
        This function processes sniffs for a discover confirm packet
        and returns 1 if seen and valid, otherwise 0 after expiry of
        timeout period
        """
        self.logger.debug("Phase 3 discover_confirm started on %s", if_name)
        #*** Start layer 2 socket for packet sniffing:
        self.logger.info("Starting socket sniff connection to interface=%s",
                            if_name)
        mysock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        mysock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        mysock.bind((if_name, ETH_P_ALL))
        self.set_promiscuous_mode(if_name, mysock)

        start_time = time.time()
        elapsed_time = 0
        result = 0
        while True:
            if elapsed_time > timeout:
                self.logger.warning("Phase 3 timeout waiting for packet")
                return 0
            self.logger.debug("sniff getting packet from socket")
            #*** Get packet from socket:
            pkt, sa_ll = mysock.recvfrom(MTU)

            #*** Read into dpkt:
            eth = dpkt.ethernet.Ethernet(pkt)
            eth_src = mac_addr(eth.src)
            eth_dst = mac_addr(eth.dst)
            eth_payload = eth.data

            #*** Ignore outgoing packets:
            pkt_type = sa_ll[2]
            if pkt_type == socket.PACKET_OUTGOING:
                self.logger.debug("sniff ignoring outgoing packet")
            else:
                if (eth_src == dpae2ctrl_mac and
                            eth_dst == ctrl2dpae_mac):
                    self.logger.debug("Matched discover confirm, src=%s "
                                            "dst=%s payload=%s",
                                            eth_src, eth_dst, eth_payload)
                    #*** Validate JSON in payload:
                    json_decode = JSON_Body(str(eth_payload))
                    if json_decode.error:
                        self.logger.error("Phase 3 packet payload is not JSON"
                                            "error=%s", json_decode.error_full)
                        return 0
                    #*** Validate required keys are present in JSON:
                    if not json_decode.validate(['hostname_dpae', 'uuid_dpae',
                                        'uuid_controller', 'if_name']):
                        self.logger.error("Validation error %s",
                                                    json_decode.error)
                        return 0

                    result = 1
                    break

            elapsed_time = time.time() - start_time
        #*** Close the socket:
        mysock.close()
        #*** Send result in queue back to the parent process:
        queue.put(result)
        return result

    def set_promiscuous_mode(self, if_name, mysock):
        """
        Set a given Ethernet interface to promiscuous mode
        so that it can receive packets destined for any
        MAC address.
        """
        #*** For setting Ethernet interface promiscuous mode:
        self.logger.info("Setting promiscuous mode on interface=%s",
                            if_name)
        ifr = Ifreq()
        ifr.ifr_ifrn = if_name
        #*** Get the flags from the interface:
        fcntl.ioctl(mysock.fileno(), SIOCGIFFLAGS, ifr)
        #*** Update flags with promiscuous mode:
        ifr.ifr_flags |= IFF_PROMISC
        #*** Apply updated flags to the interface:
        fcntl.ioctl(mysock.fileno(), SIOCSIFFLAGS, ifr)
        return 1

class Ifreq(ctypes.Structure):
    """
    Class used in setting Ethernet interface promiscuous mode
    """
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

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

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
