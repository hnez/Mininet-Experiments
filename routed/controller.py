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
from pox.lib.packet.ethernet import ethernet as Ethernet
from pox.lib.packet.arp import arp as Arp

import pox.openflow.libopenflow_01 as of
import pox.lib.addresses as addresses

log = Core.getLogger()

class RouterPort(object):
    def __init__(self, backplane, my_ip, my_netmask, my_mac, my_ofport):
        self.backbone= backplane
        self.my_ip= addresses.IPAddr(my_ip)
        self.my_netmask= addresses.IPAddr(my_netmask)
        self.my_mac= addresses.EthAddr(my_mac)
        self.my_ofport= my_ofport

        # A list of packets that could not yet be delivered
        # due to ARP resolution being in progress.
        self.packet_queue= list()

        # IP->MAC mappings learned using ARP
        self.neigh_by_ip= dict()

    def match_ip(self, ip):
        'Check if an IP is in a subnet corvered by this port'

        my= self.my_ip.toUnsigned()
        other= ip.toUnsigned()
        netmask= self.my_netmask.toUnsigned()

        return ((my & netmask) == (other & netmask))

    def _packet_send(self, packet):
        'Send an ethernet packet on this router port'

        self.backbone.packet_send(packet, self.my_ofport)

    def rule_build(self, event):
        '''
        Install a flow rule that automates the forwarding
        done in order for the packet in event to reach
        its destination.

        Returns False if no such automation can be installed yet.
        '''

        eth_fwd= event.parsed
        ippkg_fwd= eth_fwd.payload

        ip_src= ippkg_fwd.srcip
        ip_dst= ippkg_fwd.dstip

        if ip_dst in self.neigh_by_ip:
            other_mac_src= eth_fwd.src
            other_mac_dst= eth_fwd.dst
            other_ofport= event.port

            my_mac_src= self.my_mac
            my_mac_dst= self.neigh_by_ip[ip_dst]
            my_ofport= self.my_ofport

            match= of.ofp_match(
                in_port= other_ofport,
                dl_src= other_mac_src, dl_dst= other_mac_dst,
                dl_type= Ethernet.IP_TYPE,
                nw_src= ip_src, nw_dst= ip_dst
            )

            actions= list()
            actions.append(of.ofp_action_dl_addr.set_src(my_mac_src))
            actions.append(of.ofp_action_dl_addr.set_dst(my_mac_dst))
            actions.append(of.ofp_action_output(port=my_ofport))

            self.backbone.flow_mod(match, actions)

            return True

        else:
            return False

    def packet_forward(self, event):
        '''
        Manually mangle a packet and forward it to its destination.
        Kick off an ARP request and enqueue the packet if the
        destination HW address is not known yet.

        Returns true if the packet will be output on this port.
        '''

        eth_fwd= event.parsed
        ip_fwd= eth_fwd.payload
        addr_dst= ip_fwd.dstip

        if not self.match_ip(ip_fwd.dstip):
            return False

        if addr_dst in self.neigh_by_ip:
            # The HW address of the peer is known:
            #  Perform the forwarding

            eth_fwd.src= self.my_mac
            eth_fwd.dst= self.neigh_by_ip[addr_dst]

            self._packet_send(eth_fwd)

        else:
            # The HW address of the peer is not known:
            #  Kick of an ARP request and store the packet in
            #  a queue to be processed when the address is known.

            arp_out= Arp(
                hwsrc= self.my_mac, hwdst= addresses.EthAddr("ff:ff:ff:ff:ff:ff"),
                opcode= Arp.REQUEST,
                protosrc= self.my_ip, protodst= ip_fwd.dstip
            )

            eth_out= Ethernet(
                dst= addresses.EthAddr("ff:ff:ff:ff:ff:ff"), src= self.my_mac,
                type= Ethernet.ARP_TYPE, next= arp_out
            )

            self._packet_send(eth_out)
            self.packet_queue.append(event)

        return True

    def _learn_neighbour(self, neigh_ip, neigh_mac):
        'Add an IP->MAC mapping and send out enqueued packets'

        if neigh_ip not in self.neigh_by_ip:
            self.neigh_by_ip[neigh_ip]= neigh_mac

            packet_queue_old= self.packet_queue
            self.packet_queue= list()

            for packet in packet_queue_old:
                self.packet_forward(packet)

    def _on_arp_recv(self, event):
        'Handle incoming ARP packets'

        eth_in= event.parsed
        arp_in= eth_in.payload

        # Ignore ARP requests/responses for other hosts
        if (arp_in.protodst != self.my_ip):
            return

        if arp_in.opcode == Arp.REQUEST:
            # Answer request for my HW address

            arp_out= Arp(
                hwsrc= self.my_mac, hwdst= arp_in.hwsrc,
                opcode= Arp.REPLY,
                protosrc= self.my_ip, protodst= arp_in.protosrc
            )

            eth_out= Ethernet(
                dst= eth_in.src, src= self.my_mac,
                type= Ethernet.ARP_TYPE, next= arp_out
            )

            self._packet_send(eth_out)

        elif arp_in.opcode == Arp.REPLY:
            # Handle responses to my requests

            neigh_mac= arp_in.hwsrc
            neigh_ip= arp_in.protosrc

            self._learn_neighbour(neigh_ip, neigh_mac)

    def _on_ip_recv(self, event):
        '''
        Handle incoming IP packets by forwarding them
        to the backbone for forwarding to their destinations
        and for adding routing rules.
        '''

        eth_in= event.parsed

        if (eth_in.dst != self.my_mac):
            return

        self.backbone.rule_build(event)
        self.backbone.packet_forward(event)

    def on_packet_recv(self, event):
        '''
        Handle a packet that was handed down to this port
        by the RouterBackbone
        '''

        eth_in= event.parsed

        log.debug('Got packet type {} from {} to {} on ofport {}'.format(
            eth_in.type, eth_in.src, eth_in.dst, event.port)
        )

        if eth_in.type == Ethernet.ARP_TYPE:
            self._on_arp_recv(event)

        elif eth_in.type == Ethernet.IP_TYPE:
            self._on_ip_recv(event)


class RouterBackplane(object):
    def __init__(self, connection):
        self.connection= connection

        # Tell Pox to use methods in this class as callbacks
        # (At the moment only _handle_PacketIn).
        connection.addListeners(self)

        self.ports= {
            1 : RouterPort(self, '10.0.1.1', '255.255.255.0', '00:00:00:00:11:01', 1),
            2 : RouterPort(self, '10.0.2.1', '255.255.255.0', '00:00:00:00:11:02', 2),
            3 : RouterPort(self, '10.0.3.1', '255.255.255.0', '00:00:00:00:11:03', 3),
        }

    def flow_mod(self, match, actions):
        'Inject a new flow modification rule into the forwarding device'

        msg = of.ofp_flow_mod(match=match, actions=actions)
        self.connection.send(msg)

    def packet_send(self, packet, ofport):
        '''
        Tell the forwarding device to output an ethernet
        packet on one of its ports
        '''

        action= of.ofp_action_output(port=ofport)
        msg= of.ofp_packet_out(data=packet, action=action)
        self.connection.send(msg)

    def packet_forward(self, event):
        '''
        Take an ethernet frame and ask all of the router
        ports to forward it to its destination.

        Only the port responsible for the respective
        destination subnet should actually do anything here.
        '''

        success= any(
            port.packet_forward(event)
            for (ofid, port) in self.ports.items()
        )

        return success

    def rule_build(self, event):
        '''
        Take an ethernet frame and ask all of the router
        ports to create a flow rule that automates the required
        packet forwarding.

        Only the port responsible for the respective
        destination subnet should actually do anything here.
        '''

        success= any(
            port.rule_build(event)
            for (ofid, port) in self.ports.items()
        )

        return success

    def on_packet_recv(self, event):
        'Called upon reception of a valid openflow packet'

        # Delegate the actualy packet handling to the
        # corresponding router port
        port= self.ports[event.port]
        port.on_packet_recv(event)

    def _handle_PacketIn (self, event):
        '''
        The callback called by Pox upon reception of
        an openflow packet
        '''

        eth= event.parsed
        if not eth.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Forward the actual packet handling to a method
        # that does not mix CamelCase and snake_case
        # in order to not look like idiots.
        self.on_packet_recv(event)

def launch ():
    'Setup function called by Pox'

    def start_router (event):
        log.debug("Controlling %s" % (event.connection,))

        # Run a RouterBackplane instance for every incoming
        # openflow connection
        RouterBackplane(event.connection)

    Core.openflow.addListenerByName("ConnectionUp", start_router)
