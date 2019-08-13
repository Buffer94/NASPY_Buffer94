from NetInterface import *
from Monitors import *
import sys

usage = "Usage: -i [interface], [-m [mode]], [-h [help]]"
full_usage = "mode options: \n" \
             "arp: IDS system for ARP protocol." \
             "dhcp: IDS system for Rogue DHCP Attack" \
             "dns: IDS system for DNS Hijack Attack" \
             "vlan: Monitoring vlan that pass through a switch" \
             "stp: Monitoring STP Status and eventually failure" \
             "default: When no other options are chosen this script will perform all modality"

print ("Welcome to NASPy --Buffer94_Module--")

if len(sys.argv) < 3:
    print("Error, you must enter an Interface name and a modality")
    print(usage)
    sys.exit(0)

else:
    if sys.argv[1] == '-i':
        interface = sys.argv[2]
    else:
        if sys.argv[1] == '-h':
            print('%s \n %s' % (usage, full_usage))
        else:
            print (usage)
        sys.exit(0)

    mode = None
    if len(sys.argv) > 4 and sys.argv[3] == '-m':
        if sys.argv[4] == 'arp':
            mode = 'arp'
        if sys.argv[4] == 'dhcp':
            mode = 'dhcp'
        if sys.argv[4] == 'vlan':
            mode = 'vlan'
        if sys.argv[4] == 'stp':
            mode = 'stp'
        if sys.argv[4] == 'dns':
            mode = 'dns'
    else:
        mode = 'all'

if mode is None:
    print('%s \n %s' % (usage, full_usage))
    sys.exit(0)


def update_callback(pkt):
    if mode == 'all':
        if pkt.highest_layer.upper() == 'ARP':
            arp_monitor.update_arp_table(pkt)
        if pkt.highest_layer.upper() == 'BOOTP':
            dhcp_monitor.update_dhcp_servers(pkt)
        # stp_monitor.update_switches_table(pkt)

    if mode == 'dns':
        # TODO
        print('dns')

    if mode == 'dhcp' and pkt.highest_layer.upper() == 'BOOTP':
        dhcp_monitor.update_dhcp_servers(pkt)
        #net_interface.send_dhcp_discover()

    if mode == 'arp' and pkt.highest_layer.upper() == 'ARP':
        arp_monitor.update_arp_table(pkt)


def stp_update_callback(pkt):
    stp_monitor.update_switches_table(pkt)


try:
    net_interface = NetInterface(interface)
    net_interface.timeout = 35

    stp_monitor = STPMonitor()
    arp_monitor = ArpMonitor()
    dhcp_monitor = RogueDHCPMonitor()

    if mode == 'stp' or mode == 'all':
        net_interface.wait_cdp_packet()
        auth = net_interface.ssh_no_credential_connection()
        if auth:
            stp_monitor.add_switch(net_interface.take_interfaces())
            net_interface.enable_monitor_mode()

        print('start sniffing...')
        net_interface.capture = pyshark.LiveCapture(interface=net_interface.interface)
        try:
            net_interface.capture.apply_on_packets(stp_update_callback, timeout=net_interface.timeout)
        except concurrent.futures.TimeoutError:
            print('Capture finished!')

        stp_monitor.set_connected_interface_status(interface)
        stp_monitor.find_root_port(interface)

        stp_monitor.print_switches_status()

    stop = False

    while not stop:
        if mode == 'stp' or mode == 'all':
            time.sleep(35)
            print("Finding topology changes!")
            topology_cng_pkg = pyshark.LiveCapture(interface=interface, display_filter="stp.flags.tc == 1")
            topology_cng_pkg.sniff(packet_count=1, timeout=300)

            if len(topology_cng_pkg) > 0:
                print("Found topology changes!")
                stp_monitor.discover_topology_changes(interface)
            else:
                print('No changes in Topology!')
            stp_monitor.print_switches_status()

        time.sleep(20)
        if mode == 'dhcp' or mode == 'all':
            net_interface.send_dhcp_discover()

        if mode == 'dns' or mode == 'all':
            net_interface.send_dns_request()

        print('start sniffing...')
        net_interface.capture = pyshark.LiveCapture(interface=net_interface.interface)
        try:
            net_interface.capture.apply_on_packets(update_callback, timeout=net_interface.timeout)
        except concurrent.futures.TimeoutError:
            print('Capture finished!')

except (KeyboardInterrupt, RuntimeError, TypeError):
    print("Bye!!")
