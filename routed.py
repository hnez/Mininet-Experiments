from mininet.topo import Topo

class BasicTopo(Topo):
    def __init__(self):
        # Initialize topology
        super(BasicTopo, self).__init__(self)

        # Add hosts and switches
        host_arnold = self.addHost('h1', ip="10.0.1.100/24", defaultRoute="10.0.1.1")
        host_bertha = self.addHost('h2', ip="10.0.2.100/24", defaultRoute="10.0.2.1")
        host_clyde = self.addHost('h3', ip="10.0.2.100/24", defaultRoute="10.0.2.1")


        switch_central = self.addSwitch('s1')

        # Add links
        self.addLink(host_arnold, switch_central)
        self.addLink(host_bertha, switch_central)
        self.addLink(host_clyde, switch_central)


topos = {
    'basic_topo': lambda: BasicTopo()
}
