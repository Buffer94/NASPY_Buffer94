from NetInterface import *
from Monitors import STPMonitor
import time

usage = "Usage: -i [interface], -m [mode]"

print ("Welcome to NasPy --Buffer94_Module-- ####STP_DEBUG####")

interface = 'enp0s3'
mode = 'stp'

net_interface = NetInterface(interface)

net_interface.wait_cdp_packet()
net_interface.ssh_connection()

stp_monitor = STPMonitor()

net_interface.take_interfaces(stp_monitor)
net_interface.enable_monitor_mode()


def update_callback(pkt):
    if mode == 'stp':
        if pkt.highest_layer.upper() == 'STP' and (pkt.stp.type == '0x80' or pkt.stp.type == '0x80000000'):
            stp_monitor.set_root_port(packet.stp.bridge_hw, packet.eth.src)
        stp_monitor.update_switches_table(pkt)


print('start sniffing...')
net_interface.capture = pyshark.LiveCapture(interface=net_interface.interface)
try:
    net_interface.capture.apply_on_packets(update_callback, timeout=net_interface.timeout)
except Exception:
    print('Capture finished!')

while(True):
    if mode == 'stp':
        stp_monitor.find_root_port(interface)

        for switch in stp_monitor.switches_table:
            switch.print_port_status()

        # Find Topology Change
        topology_cng_capture = pyshark.LiveCapture(interface=interface, display_filter="stp.flags.tc == 1")
        try:
            topology_cng_capture.sniff(packet_count = 1, timeout=300)
        except Exception:
            print('No changes in Topology!')

        if len(topology_cng_capture) > 0:
            print("miao")
