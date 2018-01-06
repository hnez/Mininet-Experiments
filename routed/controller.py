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

        self.packet_queue= list()
        self.neigh_by_ip= dict()

    def match_ip(self, ip):
        my= self.my_ip.toUnsigned()
        other= ip.toUnsigned()
        netmask= self.my_netmask.toUnsigned()

        return ((my & netmask) == (other & netmask))

    def _packet_send(self, packet):
        self.backbone.packet_send(packet, self.my_ofport)

    def rule_build(self, event):
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
        eth_fwd= event.parsed
        ip_fwd= eth_fwd.payload
        addr_dst= ip_fwd.dstip

        if not self.match_ip(ip_fwd.dstip):
            return False

        if addr_dst in self.neigh_by_ip:
            eth_fwd.src= self.my_mac
            eth_fwd.dst= self.neigh_by_ip[addr_dst]

            self._packet_send(eth_fwd)

            return True

        else:
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

    def _learn_neighbour(self, neigh_ip, neigh_mac):
        self.neigh_by_ip[neigh_ip]= neigh_mac

        packet_queue_old= self.packet_queue
        self.packet_queue= list()

        for packet in packet_queue_old:
            self.packet_forward(packet)

    def _on_arp_recv(self, event):
        eth_in= event.parsed
        arp_in= eth_in.payload

        if (arp_in.protodst != self.my_ip):
            return

        if arp_in.opcode == Arp.REQUEST:
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
            self._learn_neighbour(arp_in.protosrc, arp_in.hwsrc)

    def _on_ip_recv(self, event):
        eth_in= event.parsed

        if (eth_in.dst != self.my_mac):
            return

        self.backbone.rule_build(event)
        self.backbone.packet_forward(event)

    def on_packet_recv(self, event):
        eth_in= event.parsed

        log.debug('Got packet type {} from {} to {} on ofport {}'.format(eth_in.type, eth_in.src, eth_in.dst, event.port))

        if eth_in.type == Ethernet.ARP_TYPE:
            self._on_arp_recv(event)

        elif eth_in.type == Ethernet.IP_TYPE:
            self._on_ip_recv(event)


class RouterBackplane(object):
    def __init__(self, connection):
        self.connection= connection
        connection.addListeners(self)

        self.ports= {
            1 : RouterPort(self, '10.0.1.1', '255.255.255.0', '00:00:00:00:11:01', 1),
            2 : RouterPort(self, '10.0.2.1', '255.255.255.0', '00:00:00:00:11:02', 2),
            3 : RouterPort(self, '10.0.3.1', '255.255.255.0', '00:00:00:00:11:03', 3),
        }

    def flow_mod(self, match, actions):
        msg = of.ofp_flow_mod(match=match, actions=actions)
        self.connection.send(msg)

    def packet_send(self, packet, ofport):
        action= of.ofp_action_output(port=ofport)
        msg= of.ofp_packet_out(data=packet, action=action)
        self.connection.send(msg)

    def rule_build(self, event):
        success= any(
            port.rule_build(event)
            for (ofid, port) in self.ports.items()
        )

        return success

    def packet_forward(self, event):
        success= any(
            port.packet_forward(event)
            for (ofid, port) in self.ports.items()
        )

        return success

    def on_packet_recv(self, event):
        port= self.ports[event.port]

        port.on_packet_recv(event)

    def _handle_PacketIn (self, event):
        eth= event.parsed
        if not eth.parsed:
            log.warning("Ignoring incomplete packet")
            return

        self.on_packet_recv(event)

def launch ():
    def start_router (event):
        log.debug("Controlling %s" % (event.connection,))
        RouterBackplane(event.connection)

    Core.openflow.addListenerByName("ConnectionUp", start_router)
