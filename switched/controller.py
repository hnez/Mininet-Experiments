# Copyright 2018 Leonard Göhrs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pox.core import core as Core

import pox.openflow.libopenflow_01 as of
import pox.lib.addresses as addresses

log = Core.getLogger()

class Switch (object):
    def __init__ (self, connection):
        self.connection= connection

        # Tell Pox to use methods in this class as callbacks
        # (At the moment only _handle_PacketIn).
        connection.addListeners(self)

        # MAC->Port mappings learned by passive
        # network observations
        self.mac_to_port= {}

    def resend_packet (self, packet_in, out_port):
        'Tell the forwarding device to output an ethernet packet on out_port'

        action= of.ofp_action_output(port=out_port)
        msg= of.ofp_packet_out(data=packet_in, action=action)

        self.connection.send(msg)

    def act_like_switch (self, packet, event):
        'Handle an input packet like a switch'

        self.mac_to_port[packet.src]= event.port

        log.debug('Forward {} - > {}'.format(packet.src, packet.dst))

        if packet.dst in self.mac_to_port:
            # The destination port is known:
            #  - Add a rule for this HW SRC->HW DST combination.
            #  - Manually send out the packet on the corresponding port.

            port_dst= self.mac_to_port[packet.dst]

            match= of.ofp_match(dl_src=packet.src, dl_dst=packet.dst)
            action= of.ofp_action_output(port=port_dst)
            msg = of.ofp_flow_mod(match=match, action=action)

            self.connection.send(msg)

            self.resend_packet(event.ofp, port_dst)

        else:
            # The destination port is not known:
            #  - Output the packet on any port

            self.resend_packet(event.ofp, of.OFPP_ALL)

    def _handle_PacketIn (self, event):
        '''
        The callback called by Pox upon reception of
        an openflow packet
        '''

        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        self.act_like_switch(packet, event)

def launch ():
    'Setup function called by Pox'

    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))

        # Run a Swtich instance for every
        # incoming openflow connection
        Switch(event.connection)

    Core.openflow.addListenerByName("ConnectionUp", start_switch)
