"""
Topology: 5 switch (1 trung tam, 4 switch con), moi switch con co 3 host
              
                         [s1] (Trung tam)
                        /  |  |  \
                      /    |  |    \
                    /      |  |      \
                  [s2]   [s3] [s4]   [s5]
                 / | \  / | \ / | \  / | \
                3 host 3 host 3 host 3 host
               (h1-h3)(h4-h6)(h7-h9)(h10-h12)

Chay: sudo python3 topo_2sw_4host.py
"""
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def run():
    setLogLevel('info')
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    # Controller
    c0 = net.addController('c0', ip='127.0.0.1', port=6633)

    # 5 switch
    s1 = net.addSwitch('s1') # Switch trung tam
    s2 = net.addSwitch('s2') # Switch con 1
    s3 = net.addSwitch('s3') # Switch con 2
    s4 = net.addSwitch('s4') # Switch con 3
    s5 = net.addSwitch('s5') # Switch con 4

    # Switch con 1 (s2): 3 host
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:01:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:01:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:01:00:03')

    # Switch con 2 (s3): 3 host
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:02:00:01')
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:02:00:02')
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:02:00:03')

    # Switch con 3 (s4): 3 host
    h7 = net.addHost('h7', ip='10.0.0.7/24', mac='00:00:00:03:00:01')
    h8 = net.addHost('h8', ip='10.0.0.8/24', mac='00:00:00:03:00:02')
    h9 = net.addHost('h9', ip='10.0.0.9/24', mac='00:00:00:03:00:03')

    # Switch con 4 (s5): 3 host
    h10 = net.addHost('h10', ip='10.0.0.10/24', mac='00:00:00:04:00:01')
    h11 = net.addHost('h11', ip='10.0.0.11/24', mac='00:00:00:04:00:02')
    h12 = net.addHost('h12', ip='10.0.0.12/24', mac='00:00:00:04:00:03')

    # Ket noi host vao switch con 1 (s2)
    net.addLink(h1, s2)
    net.addLink(h2, s2)
    net.addLink(h3, s2)

    # Ket noi host vao switch con 2 (s3)
    net.addLink(h4, s3)
    net.addLink(h5, s3)
    net.addLink(h6, s3)

    # Ket noi host vao switch con 3 (s4)
    net.addLink(h7, s4)
    net.addLink(h8, s4)
    net.addLink(h9, s4)

    # Ket noi host vao switch con 4 (s5)
    net.addLink(h10, s5)
    net.addLink(h11, s5)
    net.addLink(h12, s5)

    # Noi 4 switch con vao switch trung tam
    net.addLink(s2, s1)
    net.addLink(s3, s1)
    net.addLink(s4, s1)
    net.addLink(s5, s1)

    net.start()
    print("\n=== TOPOLOGY ===")
    print("  Trung tam: SW1")
    print("  SW2 (Con 1): h1=10.0.0.1 den h3=10.0.0.3")
    print("  SW3 (Con 2): h4=10.0.0.4 den h6=10.0.0.6")
    print("  SW4 (Con 3): h7=10.0.0.7 den h9=10.0.0.9")
    print("  SW5 (Con 4): h10=10.0.0.10 den h12=10.0.0.12")
    print("  [SW2] [SW3] [SW4] [SW5]")
    print("    \    |     |    /")
    print("     \   |     |   /")
    print("         [SW1]      ")
    print("================\n")

    print("[*] Sẵn sàng! Bạn có thể tự gõ lệnh sinh traffic (ví dụ: pingall, iperf, hping3) từ CLI ngay bây giờ.\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
