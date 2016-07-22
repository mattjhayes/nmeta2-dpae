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

#*** For socket operation:
import socket

#*** General imports:
import time

#*** Import dpkt for packet parsing:
import dpkt

#*** Logging imports:
import logging
import logging.handlers
import coloredlogs

#*** For setting Ethernet interface promiscuous mode:
import ctypes
import fcntl

#*** Constants for setting Ethernet interface promiscuous mode:
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

#*** MAC destinations to not forward:
MAC_LLDP_NEAREST_BRIDGE = '01:80:c2:00:00:0e'
MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff'
DO_NOT_FORWARD_MACS = (MAC_LLDP_NEAREST_BRIDGE, MAC_BROADCAST)

#*** TBD, this should be autodetected:
MTU = 6000

#*** TBD, this should be validated:
ETH_P_ALL = 3

class Sniff(object):
    """
    This class is instantiated by nmeta_dpae.py and provides methods to
    sniff and process inbound packets on a given interface
    """
    def __init__(self, _config, tc):
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
        #*** Variable for accessing tc class:
        self.tc = tc

    def sniff_run(self, if_name, tc, tc_policy, queue):
        """
        This function sniffs packets from a NIC.
        It passes the packets to the tc module for classification and
        returns any TC results to parent process via a queue.

        In active mode it also sends the processed packet back to
        the switch
        """

        #*** Get the tc mode (active or passive):
        tc_mode = tc_policy.tc_mode(if_name)
        self.logger.debug("tc_mode is %s", tc_mode)

        #*** Start layer 2 socket for packet sniffing:
        self.logger.info("Starting socket sniff connection to interface=%s",
                            if_name)
        mysock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        mysock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        mysock.bind((if_name, ETH_P_ALL))

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

            #*** Call TC function to process packet:
            tc_result = self.tc.classify_dpkt(pkt, pkt_receive_timestamp,
                                                            if_name)
            if 'type' in tc_result:
                if tc_result['type'] != 'none':
                    #*** Send to control plane:
                    self.logger.debug("Sending result to control plane: %s",
                                                            tc_result)
                    queue.put(tc_result)

            if tc_mode == 'active':
                #*** Some types of packets shouldn't be forwarded:
                #*** Read into dpkt (expensive?):
                eth = dpkt.ethernet.Ethernet(pkt)
                if mac_addr(eth.dst) in DO_NOT_FORWARD_MACS:
                    continue
                #*** Active Mode: send the packet back to the switch:
                try:
                    mysock.send(pkt)
                except Exception, e:
                    self.logger.error("Active mode sending packet failed: %s",
                                                e, exc_info=True)

    def discover_confirm(self, if_name, dpae2ctrl_mac, ctrl2dpae_mac,
                        dpae_ethertype, timeout):
        """
        This function processes sniffs for a discover confirm packet
        and returns 1 if seen and valid, otherwise 0 after expiry of
        timeout period
        """
        #*** Start layer 2 socket for packet sniffing:
        self.logger.info("Starting socket sniff connection to interface=%s",
                            if_name)
        mysock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        mysock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        mysock.bind((if_name, ETH_P_ALL))

        start_time = time.time()
        elapsed_time = 0
        payload = ''

        while True:
            if elapsed_time > timeout:
                self.logger.warning("Phase 3 timeout waiting for packet")
                break
            self.logger.debug("sniff getting packet from socket")
            #*** Get packet from socket:
            pkt, sa_ll = mysock.recvfrom(MTU)

            #*** Read into dpkt:
            eth = dpkt.ethernet.Ethernet(pkt)
            eth_src = mac_addr(eth.src)
            eth_dst = mac_addr(eth.dst)
            eth_type = eth.type
            eth_payload = eth.data

            #*** Ignore outgoing packets:
            pkt_type = sa_ll[2]
            if pkt_type == socket.PACKET_OUTGOING:
                self.logger.debug("Ignoring outgoing packet")
            else:
                if (eth_src == dpae2ctrl_mac and eth_dst == ctrl2dpae_mac and
                                                eth_type == dpae_ethertype):
                    self.logger.debug("Matched discover confirm, src=%s "
                                            "dst=%s payload=%s",
                                            eth_src, eth_dst, eth_payload)
                    payload = eth_payload
                    break
                else:
                    self.logger.debug("Ignoring packet src=%s dst=%s type=%s",
                                       eth_src, eth_dst, eth_type)
            elapsed_time = time.time() - start_time

        #*** Close the socket:
        mysock.close()
        #*** Return the packet payload (if any, otherwise empty string):
        return payload

    def set_promiscuous_mode(self, if_name):
        """
        Set a given Ethernet interface to promiscuous mode
        so that it can receive packets destined for any
        MAC address.
        """
        #*** For setting Ethernet interface promiscuous mode:
        self.logger.info("Setting promiscuous mode on interface=%s",
                            if_name)

        #*** Create a socket to use:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        #*** Create an instance of Ifreq class to use and assign interface:
        ifr = Ifreq()
        ifr.ifr_ifrn = if_name

        #*** Get the flags from the interface:
        fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)

        #*** Update flags with promiscuous mode:
        ifr.ifr_flags |= IFF_PROMISC

        #*** Apply updated flags to the interface:
        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)

        sock.close()
        return 1

    def get_promiscuous_mode(self, if_name):
        """
        Return the promiscuous mode of an interface.
        1 is promiscuous mode enabled
        0 is promiscuous mode disabled
        """
        self.logger.info("Checking promiscuous mode on interface=%s",
                            if_name)
        promisc = 0

        #*** Create a socket to use:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        #*** Create an instance of Ifreq class to use and assign interface:
        ifr = Ifreq()
        ifr.ifr_ifrn = if_name

        #*** Get the flags from the interface:
        fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)

        #*** Check the status of the promiscuous flag:
        if ifr.ifr_flags & IFF_PROMISC:
            promisc = 1
        self.logger.info("interface=%s flags=%s promiscuous=%s", if_name,
                    bin(ifr.ifr_flags), promisc)
        sock.close()
        return promisc

class Ifreq(ctypes.Structure):
    """
    Class used in setting Ethernet interface promiscuous mode
    """
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
