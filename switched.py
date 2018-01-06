from mininet.topo import Topo

class BasicTopo(Topo):
    def __init__(self):
        # Initialize topology
        super(BasicTopo, self).__init__(self)

        # Add hosts and switches
        host_arnold = self.addHost('h1')
        host_bertha = self.addHost('h2')
        host_clyde = self.addHost('h3')


        switch_central = self.addSwitch('s1')

        # Add links
        self.addLink(host_arnold, switch_central)
        self.addLink(host_bertha, switch_central)
        self.addLink(host_clyde, switch_central)


topos = {
    'basic_topo': lambda: BasicTopo()
}
