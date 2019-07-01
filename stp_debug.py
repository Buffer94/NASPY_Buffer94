from NetInterface import *
from Monitors import STPMonitor
import sys

usage = "Usage: -i [interface], -m [mode]"

print ("Welcome to NasPy --Buffer94_Module-- ####STP_DEBUG####")
# print (usage)

interface = 'enp0s3'
mode = 'stp'

net_interface = NetInterface(interface)

net_interface.wait_cdp_packet()
net_interface.ssh_connection()

if mode == 'dhcp' or mode == 'all':
    net_interface.send_dhcp_discover()

if mode == 'dns' or mode == 'all':
    net_interface.send_dns_request()


stp_monitor = STPMonitor()

if mode == 'stp':
    net_interface.take_interfaces(stp_monitor)

net_interface.enable_monitor_mode()

def update_callback(pkt):
    if mode == 'stp' and pkt.highest_layer.upper() == 'STP':
        stp_monitor.update_switches_table(pkt)

print('start sniffing...')
net_interface.capture = pyshark.LiveCapture(interface=net_interface.interface)
net_interface.capture.apply_on_packets(update_callback, timeout=net_interface.timeout)

