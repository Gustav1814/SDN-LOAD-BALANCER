from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, Host
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.util import pmonitor
from time import sleep

class CustomTopo(Topo):
    def build(self):
        # Add switch
        switch = self.addSwitch('s1')

        # Add intermediary node
        #intermediary = self.addHost('vip', ip='10.0.0.254/24',mac='00:00:00:00:00:FF')

        # Add servers
        servers = []
        for i in range(1, 5):
            server = self.addHost(f'server{i}', ip=f'10.0.0.{100 + i}/24')
            servers.append(server)

        # Add clients
        clients = []
        for i in range(1, 10):
            client = self.addHost(f'pc{i}', ip=f'10.0.0.{10 + i}/24')
            clients.append(client)
        # Connect intermediary to switch
        #self.addLink(intermediary, switch)

        # Connect servers to switch
        for server in servers:
            self.addLink(server, switch)

        # Connect clients to switch
        for client in clients:
            self.addLink(client, switch)

def start_web_servers(net):
    # Start a web server on each server host
    print("Starting web servers on server hosts...")
    for i in range(1, 5):
        server = net.get(f'server{i}')
        # Start a simple HTTP server on port 80
        server.cmd('python3 -m http.server 80 &')

    # Give servers some time to start up
    sleep(5)
    print("Web servers started.")

def run():
    net = Mininet(
        topo=CustomTopo(),
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),  # Adjust IP and port if needed
        switch=OVSKernelSwitch,
        link=TCLink
    )

    net.start()

    # Print host IPs to verify connectivity
    print("Network setup complete. Host IPs:")
    for host in net.hosts:
        print(f"{host.name} has MAC address {host.MAC()} and is connected to {host.intf()}")

    # Start web servers on the server hosts
    start_web_servers(net)
    
    for i in range(1, 10):
        net.get(f'pc{i}').cmd(f'echo "nameserver 127.0.0.1" > /etc/resolv.conf')

    # Add intermediary (VIP) testing command
    print("\nTesting connectivity via switch...")
    #print(net.pingAll())

    CLI(net)
    net.stop()

if __name__ == '__main__':
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel('info')
    run()
