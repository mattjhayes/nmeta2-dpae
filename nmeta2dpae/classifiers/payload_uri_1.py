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
It defines a custom traffic classifier
.
To create your own custom classifier, copy this example to a new
file in the same directory and update the code as required.
Call it from nmeta by specifying the name of the file (without the
.py) in main_policy.yaml
.
Classifiers are called per packet, so performance is important
.
"""

class Classifier(object):
    """
    A custom classifier module for import by nmeta2
    """
    def __init__(self, logger):
        """
        Initialise the classifier
        """
        self.logger = logger

    def classifier(self, flow):
        """
        A really basic HTTP URI classifier to demonstrate ability
        to differentiate based on a payload characteristic.
        .
        This method is passed a Flow class object that holds the
        current context of the flow
        .
        It returns a dictionary specifying a key/value of QoS treatment to
        take (or not if no classification determination made).
        .
        Only works on TCP.
        """
        #*** Maximum packets to accumulate in a flow before making a
        #***  classification:
        _max_packets = 7

        #*** URI to match:
        _match_uri = 'foo'

        #*** QoS actions to take:
        _qos_action_match = 'constrained_bw'
        _qos_action_no_match = 'default_priority'

        #*** Dictionary to hold classification results:
        _results = {}

        if flow.packet_count >= _max_packets and not flow.finalised:
            #*** Reached our maximum packet count so do some classification:
            self.logger.debug("Reached max packets count, finalising")
            flow.finalised = 1

            #*** Decide actions based on the URI:
            if TBD:
                #*** Matched URI:
                _results['qos_treatment'] = _qos_action
            else:
                #*** Doesn't match URI:
                _results['qos_treatment'] = _qos_action_no_match
            self.logger.debug("Decided on results %s", _results)

        return _results
