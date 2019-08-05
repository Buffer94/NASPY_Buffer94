from NetInterface import *
from Monitors import STPMonitor
from Monitors import VlanMonitor

usage = "Usage: -i [interface], -m [mode]"

print ("Welcome to NasPy --Buffer94_Module-- ####STP_DEBUG####")

interface = 'enp0s3'

net_interface = NetInterface(interface)
net_interface.timeout = 20

# def parameterized_ssh_connection(self, switch_ip, switch_name, switch_pwd, switch_en_pwd, switch_interface,
#                                      attempts=0):

# net_interface.wait_cdp_packet()
# net_interface.ssh_connection()

net_interface.parameterized_ssh_connection('10.0.1.102', 'switch2', 'ciki', 'ciki', 'GigabitEthernet1/3')

stp_monitor = STPMonitor()
# vlan_monitor = VlanMonitor()

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
except Exception as e:
    print(">>>>ERROR<<<< /n %s /n >>>>End_Error<<<<" % e)
    print('Capture finished!')

# stp_monitor.find_root_port(interface)
#
# stp_monitor.print_switches_status()
while(True):
        stp_monitor.set_connected_interface_status(interface)
        stp_monitor.find_root_port(interface)

        stp_monitor.print_switches_status()
        #TODO
        #add a way to escape.

        print("Finding topology changes!")
        topology_cng_pkg = pyshark.LiveCapture(interface=interface, display_filter="stp.flags.tc == 1")
        try:
            topology_cng_pkg.sniff(packet_count=1, timeout=300)

            if len(topology_cng_pkg) > 0:
                print("Found topology changes!")
                stp_monitor.discover_topology_changes(interface)
                stp_monitor.print_switches_status()
            else:
                print('No changes in Topology!')
        except Exception as e:
            print('No changes in Topology! %s' % e.with_traceback())
