from NetInterface import *
from Monitors import STPMonitor
import concurrent

print ("Welcome to NasPy --Buffer94_Module-- ####STP_DEBUG####")

interface = 'enp0s3'

try:
    net_interface = NetInterface(interface)
    net_interface.timeout = 35

    net_interface.wait_cdp_packet()
    auth = net_interface.ssh_no_credential_connection()

    stp_monitor = STPMonitor()

    if auth:
        stp_monitor.add_switch(net_interface.take_interfaces())
        net_interface.enable_monitor_mode()

    def update_callback(pkt):
        # if pkt.highest_layer.upper() == 'STP' and (pkt.stp.type == '0x80' or pkt.stp.type == '0x80000000'):
        #     stp_monitor.set_root_port(packet.stp.bridge_hw, packet.eth.src)
        stp_monitor.update_switches_table(pkt)


    print('start sniffing...')
    net_interface.capture = pyshark.LiveCapture(interface=net_interface.interface)
    try:
        net_interface.capture.apply_on_packets(update_callback, timeout=net_interface.timeout)
    except concurrent.futures.TimeoutError:
        print('Capture finished!')

    stp_monitor.set_connected_interface_status(interface)
    stp_monitor.find_root_port(interface)

    stp_monitor.print_switches_status()

    while True:
        time.sleep(20)
        print("Finding topology changes!")
        topology_cng_pkg = pyshark.LiveCapture(interface=interface, display_filter="stp.flags.tc == 1")

        topology_cng_pkg.sniff(packet_count=1, timeout=300)

        if len(topology_cng_pkg) > 0:
            print("Found topology changes!")
            stp_monitor.discover_topology_changes(interface)
            stp_monitor.print_switches_status()
        else:
            print('No changes in Topology!')

except (KeyboardInterrupt, RuntimeError, TypeError):
    print("Bye!!")