import pox.lib.addresses as addresses
from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Switch (object):
    def __init__ (self, connection):
        self.connection= connection
        self.mac_to_port= {}

        connection.addListeners(self)

    def resend_packet (self, packet_in, out_port):
        action= of.ofp_action_output(port=out_port)
        msg= of.ofp_packet_out(data=packet_in, action=action)

        self.connection.send(msg)

    def act_like_switch (self, packet, event):
        self.mac_to_port[packet.src]= event.port

        log.debug('Forward {} - > {}'.format(packet.src, packet.dst))

        if packet.dst in self.mac_to_port:
            port_dst= self.mac_to_port[packet.dst]

            match= of.ofp_match(dl_src=packet.src, dl_dst=packet.dst)
            action= of.ofp_action_output(port=port_dst)
            msg = of.ofp_flow_mod(match=match, action=action)

            self.connection.send(msg)

            self.resend_packet(event.ofp, port_dst)

        else:
            self.resend_packet(event.ofp, of.OFPP_ALL)

    def _handle_PacketIn (self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        self.act_like_switch(packet, event)

def launch ():
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Switch(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
