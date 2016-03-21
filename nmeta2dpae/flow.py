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
It provides an abstraction for a TCP flow that links to
a MongoDB database and changes to the context of the flow
that a supplied packet belongs to
.
Version 2.x Toulouse Code
"""

#*** For packet methods:
import socket

#*** Import dpkt for packet parsing:
import dpkt

#*** For hashing flow 5-tuples:
import hashlib

class Flow(object):
    """
    An object that represents a flow that we are classifying

    Intended to provide an abstraction of a flow that classifiers
    can use to make determinations without having to understand
    implementations such as database lookups etc.

    Variables available for Classifiers (assumes class instantiated as
    an object called 'flow'):

        # Variables for the current packet:
        flow.ip_src         # IP source address of latest packet in flow
        flow.ip_dst         # IP dest address of latest packet in flow
        flow.tcp_src        # TCP source port of latest packet in flow
        flow.tcp_dst        # TCP dest port of latest packet in flow
        flow.packet_length  # Length in bytes of the current packet on wire
        flow.packet_direction   # c2s (client to server), s2c or unknown

        # Variables for the whole flow:
        flow.finalised      # A classification has been made
        flow.packet_count   # Unique packets registered for the flow
        flow.client         # The IP that is the originator of the TCP
                            #  session (if known, otherwise 0)
        flow.server         # The IP that is the destination of the TCP session
                            #  session (if known, otherwise 0)

    Methods available for Classifiers (assumes class instantiated as
    an object called 'flow'):
        flow.max_packet_size()           # Size of largest packet in the flow
        flow.max_interpacket_interval()  # TBD
        flow.min_interpacket_interval()  # TBD

    Challenges:
     - duplicate packets
     - IP fragments (not handled)
     - Flow reuse - TCP source port reused (not handled - yet)
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
        self.packet_length = 0
        self.packet_count = 0
        self.fcip_doc = {}
        self.fcip_hash = 0
        self.client = 0
        self.server = 0
        self.packet_direction = 'unknown'

    def ingest_packet(self, pkt, pkt_receive_timestamp):
        """
        Ingest a packet and put the flow object into the context
        of the flow that the packet belongs to.
        """
        #*** Packet length on the wire:
        self.packet_length = len(pkt)
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
            #*** Get flow direction (which way is TCP initiated). Client is
            #***  the end that sends the initial TCP SYN:
            if _is_tcp_syn(tcp.flags):
                self.logger.debug("Matched TCP SYN, src_ip=%s", ip_src)
                self.client = ip_src
                self.server = ip_dst

            #*** Neither direction found, so add to FCIP database:
            self.fcip_doc = {'hash': self.fcip_hash, 'ip_A': ip_src,
                        'ip_B': ip_dst, 'port_A': tcp_src, 'port_B': tcp_dst,
                        'proto': proto, 'finalised': 0, 'packet_count': 1,
                        'packet_timestamps': [pkt_receive_timestamp,],
                        'tcp_flags': [tcp.flags,],
                        'packet_lengths': [self.packet_length,],
                        'client': self.client,
                        'server': self.server,
                        'packet_directions': ['c2s',]}
            self.logger.debug("FCIP: Adding record for %s to DB",
                                                self.fcip_doc)
            db_result = self.fcip.insert_one(self.fcip_doc)
        elif self.fcip_doc['finalised']:
            #*** The flow is already finalised so do nothing:
            pass
        else:
            #*** We've found the flow in the FCIP database, now update it:
            self.logger.debug("FCIP: found existing record %s", self.fcip_doc)
            #*** Rate this packet as c2s or s2c direction:
            if self.client == ip_src:
                self.packet_direction = 'c2s'
            elif self.client == ip_dst:
                self.packet_direction = 's2c'
            else:
                self.packet_direction = 'unknown'
            #*** Increment packet count. Is it at max?:
            self.fcip_doc['packet_count'] += 1
            if self.fcip_doc['packet_count'] >= self.max_packet_count:
                #*** TBD
                self.fcip_doc['finalised'] = 1
            #*** Add packet timestamps, tcp flags etc:
            self.fcip_doc['packet_timestamps'].append(pkt_receive_timestamp)
            self.fcip_doc['tcp_flags'].append(tcp.flags)
            self.fcip_doc['packet_lengths'].append(self.packet_length)
            self.fcip_doc['packet_directions'].append(self.packet_direction)
            #*** Write updated FCIP data back to database:
            db_result = self.fcip.update_one({'hash': self.fcip_hash},
                {'$set': {'packet_count': self.fcip_doc['packet_count'],
                    'finalised': self.fcip_doc['finalised'],
                    'packet_timestamps': self.fcip_doc['packet_timestamps'],
                    'tcp_flags': self.fcip_doc['tcp_flags'],
                    'packet_lengths': self.fcip_doc['packet_lengths'],
                    'packet_directions': self.fcip_doc['packet_directions']
                        },})
            #*** Tests:
            self.logger.debug("max_packet_size is %s", self.max_packet_size())
            self.logger.debug("max_interpacket_interval is %s",
                                            self.max_interpacket_interval())
            self.logger.debug("min_interpacket_interval is %s",
                                            self.min_interpacket_interval())

    def max_packet_size(self):
        """
        Return the size of the largest packet in the flow (in either direction)
        """
        return max(self.fcip_doc['packet_lengths'])

    def max_interpacket_interval(self):
        """
        Return the size of the largest inter-packet time interval
        in the flow (assessed per direction in flow)
        """
        max_c2s = 0
        max_s2c = 0
        count_c2s = 0
        count_s2c = 0
        prev_c2s_idx = 0
        prev_s2c_idx = 0
        for idx, direction in enumerate(self.fcip_doc['packet_directions']):
            if direction == 'c2s':
                count_c2s += 1
                if count_c2s > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_c2s_idx]
                    delta = current_ts - prev_ts
                    if delta > max_c2s:
                        max_c2s = delta
                    prev_c2s_idx = idx
            elif direction == 's2c':
                count_s2c += 1
                if count_s2c > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_s2c_idx]
                    delta = current_ts - prev_ts
                    if delta > max_s2c:
                        max_s2c = delta
                    prev_s2c_idx = idx
            else:
                #*** Don't know direction so ignore:
                pass
        #*** Return the largest interpacket delay overall:
        if max_c2s > max_s2c:
            return max_c2s
        else:
            return max_s2c

    def min_interpacket_interval(self):
        """
        Return the size of the smallest inter-packet time interval
        in the flow (assessed per direction in flow)
        """
        min_c2s = 0
        min_s2c = 0
        count_c2s = 0
        count_s2c = 0
        prev_c2s_idx = 0
        prev_s2c_idx = 0
        for idx, direction in enumerate(self.fcip_doc['packet_directions']):
            if direction == 'c2s':
                count_c2s += 1
                if count_c2s > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_c2s_idx]
                    delta = current_ts - prev_ts
                    if not min_c2s or delta < min_c2s:
                        min_c2s = delta
                    prev_c2s_idx = idx
            elif direction == 's2c':
                count_s2c += 1
                if count_s2c > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_s2c_idx]
                    delta = current_ts - prev_ts
                    if not min_s2c or delta < min_s2c:
                        min_s2c = delta
                    prev_s2c_idx = idx
            else:
                #*** Don't know direction so ignore:
                pass
        #*** Return the smallest interpacket delay overall, watch out for
        #***  where we didn't get a calculation (don't return 0 unless both 0):
        if not min_s2c:
            #*** min_s2c not set so return min_c2s as it might be:
            return min_c2s
        elif 0 < min_c2s < min_s2c:
            return min_c2s
        else:
            return min_s2c

def _is_tcp_syn(tcp_flags):
    """
    Passed a TCP flags object and return 1 if it
    contains a TCP SYN and no other flags
    """
    if tcp_flags == 2:
        return 1
    else:
        return 0

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
