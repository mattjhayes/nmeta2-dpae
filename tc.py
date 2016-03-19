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
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide network identity and flow metadata.
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

import socket

import struct

#*** Import dpkt for packet parsing:
import dpkt

#*** mongodb Database Import:
from pymongo import MongoClient

#*** For hashing flow 5-tuples:
import hashlib

#*** For performance tuning timing:
import time

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
        #*** Initialise Identity Harvest flags (they get set at DPAE join time)
        self.id_arp = 0
        self.id_lldp = 0
        self.id_dns = 0
        self.id_dhcp = 0
        #*** Initialise list for TC classifiers to run:
        self.classifiers = []

        #*** Start mongodb:
        self.logger.info("Connecting to mongodb database...")
        self.mongo_addr = _config.get_value("mongo_addr")
        self.mongo_port = _config.get_value("mongo_port")
        mongo_client = MongoClient(self.mongo_addr, self.mongo_port)

        #*** Connect to specific databases and collections in mongodb:
        #*** FCIP (Flow Classification in Progress) database:
        db_fcip = mongo_client.fcip_database
        self.fcip = db_fcip.fcip

        #*** DPAE database - delete all previous entries:
        result = self.fcip.delete_many({})
        self.logger.info("Initialising FCIP database, Deleted %s previous "
                "entries from dbdpae", result.deleted_count)

        #*** Database index for performance:
        self.fcip.create_index([("hash", 1)])

    def classify_dpkt(self, pkt, pkt_receive_timestamp, if_name):
        """
        Perform traffic classification on a packet
        using dpkt for packet parsing
        """
        result = {}
        ip = 0
        udp = 0
        tcp = 0
        #*** Read into dpkt:
        eth = dpkt.ethernet.Ethernet(pkt)
        #*** Set local variables for efficient access, speed is critical...
        eth_src = mac_addr(eth.src)
        eth_dst = mac_addr(eth.dst)
        eth_type = eth.type
        self.logger.debug("packet src=%s dst=%s ethtype=%s", eth_src,
                eth_dst, eth_type)
        if eth_type == 2048:
            self.logger.debug("its IP, eth_type is %s", eth_type)
            ip = eth.data
            ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
            ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)
            #*** Check if UDP or TCP:
            if ip.p == 6:
                tcp = ip.data
                tcp_src = tcp.sport
                tcp_dst = tcp.dport
                self.logger.debug("It's TCP, src_port=%s dst_port=%s", tcp_src,
                                        tcp_dst)
            elif ip.p == 17:
                udp = ip.data
                udp_src = udp.sport
                udp_dst = udp.dport
                self.logger.debug("It's UDP, src_port=%s dst_port=%s", udp_src,
                                        udp_dst)
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

        if tcp:
            #*** Create a flow object for classifiers to work with:
            flow = Flow(self.fcip, self.logger)
            flow.ingest_packet(pkt)

        #*** Check to see if we have any traffic classifiers to run:
        for tc_type, tc_name in self.classifiers:
            self.logger.debug("Checking packet against tc_type=%s tc_name=%s",
                                    tc_type, tc_name)
            #*** TBD, do something here, pass it the flow object...

        self.logger.debug("Unknown packet, type=%s", eth.type)
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

class Flow(object):
    """
    An object that represents a flow that we are classifying

    Intended to provide an abstraction of a flow that classifiers
    can use to make determinations without having to understand
    implementations such as database lookups etc.

    Variables Exposed for Classifiers (assumes class instantiated as
    an object called 'flow'):
        flow.finalised      # A classification has been made
        flow.packet_count   # Unique packets registered for the flow
        ip_src              # IP source address of latest packet in flow
        ip_dst              # IP dest address of latest packet in flow
        tcp_src             # TCP source port of latest packet in flow
        tcp_dst             # TCP dest port of latest packet in flow

    Challenges:
     - duplicate packets
     - IP fragments (not handled)
     - Flow reuse (not handled - yet)
    """
    def __init__(self, fcip, logger):
        """
        Initialise an instance of the Flow class for a new
        flow. Passed layer 3/4 parameters.
        Add an entry to the FCIP database if it doesn't
        already exist. If it does exist, update it.
        Only works for TCP at this stage.
        """
        self.fcip = fcip
        self.logger = logger
        #*** Maximum packets in a flow before finalising:
        self.max_packet_count = 10
        #*** Initialise flow variables:
        self.finalised = 0
        self.packet_count = 0
        self.fcip_doc = {}
        self.fcip_hash = 0

    def ingest_packet(self, pkt):
        """
        Ingest a packet and put the flow object into the context
        of the flow that the packet belongs to.
        """
        #*** Read into dpkt:
        eth = dpkt.ethernet.Ethernet(pkt)
        eth_src = mac_addr(eth.src)
        eth_dst = mac_addr(eth.dst)
        eth_type = eth.type
        #*** We only support IPv4 (TBD: add IPv6 support):
        if eth_type != 2048:
            self.logger.error("Non IPv4 packet, eth_type is %s", eth_type)
            return 0
        ip = eth.data
        ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
        ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)
        #*** We only support TCP:
        if ip.p != 6:
            self.logger.error("Non TCP packet, ip_proto=%s",
                                        ip.p)
            return 0
        proto = 'tcp'
        tcp = ip.data
        tcp_src = tcp.sport
        tcp_dst = tcp.dport
        #*** Generate a hash unique to flow for packets in either direction
        self.fcip_hash = hash_5tuple(ip_src, ip_dst, tcp_src, tcp_dst, proto)
        self.logger.debug("FCIP hash=%s", self.fcip_hash)
        #*** Check to see if we already know this identity:
        db_data = {'hash': self.fcip_hash}
        self.fcip_doc = self.fcip.find_one(db_data)
        if not self.fcip_doc:
            #*** Get server direction:
            #direction = _get_direction(
            #*** Neither direction found, so add to FCIP database:
            db_data_full = {'hash': self.fcip_hash, 'ip_A': ip_src,
                        'ip_B': ip_dst, 'port_A': tcp_src, 'port_B': tcp_dst,
                        'proto': proto, 'finalised': 0, 'packet_count': 1}
            self.logger.debug("FCIP: Adding record for %s to DB",
                                                db_data_full)
            db_result = self.fcip.insert_one(db_data_full)
        elif self.fcip_doc['finalised']:
            #*** The flow is already finalised so do nothing:
            pass
        else:
            #*** We've found the flow in the FCIP database, now update it:
            self.logger.debug("FCIP: found existing record %s", self.fcip_doc)
            #*** Increment packet count. Is it at max?:
            self.fcip_doc['packet_count'] += 1
            if self.fcip_doc['packet_count'] >= self.max_packet_count:
                #*** TBD
                self.fcip_doc['finalised'] = 1
            #*** Write updated FCIP data back to database:
            db_result = self.fcip.update_one({'hash': self.fcip_hash},
                {'$set': {'packet_count': self.fcip_doc['packet_count'],
                        'finalised': self.fcip_doc['finalised']},})

def hash_5tuple(ip_A, ip_B, tp_src, tp_dst, proto):
    """
    Generate a predictable hash for the 5-tuple which is the
    same not matter which direction the traffic is travelling
    """
    if ip_A > ip_B:
        direction = 1
    elif ip_B > ip_A:
        direction = 2
    elif tp_src > tp_dst:
        direction = 1
    elif tp_dst > tp_src:
        direction = 2
    else:
        direction = 1
    hash_5t = hashlib.md5()
    if direction == 1:
        flow_tuple = (ip_A, ip_B, tp_src, tp_dst, proto)
    else:
        flow_tuple = (ip_B, ip_A, tp_dst, tp_src, proto)
    flow_tuple_as_string = str(flow_tuple)
    hash_5t.update(flow_tuple_as_string)
    return hash_5t.hexdigest()

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
