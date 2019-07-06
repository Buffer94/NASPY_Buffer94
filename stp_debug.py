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

if mode == 'stp':
    timeout = 10
    for switch in stp_monitor.switches_table:
        priority_min = 60000
        MAC_min = 'null'
        root_port = 'null'
        blocked_port = switch.get_blocked_port()
        if len(blocked_port) > 1:
            for port in blocked_port:
                print("I'm waiting")
                time.sleep(timeout * 2)
                print("I've waited")
                net_interface.ssh.reconnect(switch.ip, switch.name, switch.password, switch.en_password,
                                            switch.connected_interface, timeout)
                print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                print("bridge_id: %s" % switch.bridge_id)
                port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                   display_filter="stp && stp.bridge.hw != %s" % switch.bridge_id)
                net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                try:
                    port_capture.sniff(packet_count=1, timeout=timeout)
                except Exception:
                    print('Capture on %s finished!' % port.name)
                pkt = port_capture[0]
                print("Eth current: %s" %pkt.stp.bridge_hw)
                if int(pkt.stp.bridge_prio) < priority_min:
                    print("Priority Check!")
                    priority_min = int(pkt.stp.bridge_prio)
                    MAC_min = pkt.stp.bridge_hw
                    root_port = port.MAC
                else:
                    if MAC_min == 'null':
                        print("First assignment!")
                        priority_min = int(pkt.stp.bridge_prio)
                        MAC_min = pkt.stp.bridge_hw
                        root_port = port.MAC
                    else:
                        if int(pkt.stp.bridge_prio) == priority_min:
                            print("I'm comparing!")
                            raw_mac_min = ''
                            raw_mac_curr = ''
                            mac_parts_min = MAC_min.split(':')
                            for part in mac_parts_min:
                                raw_mac_min += part
                            mac_parts_curr = pkt.stp.bridge_hw.split(':')
                            for part in mac_parts_curr:
                                raw_mac_curr += part

                            int_mac_min = int(raw_mac_min, 16)
                            int_mac_curr = int(raw_mac_curr, 16)

                            if int_mac_curr < int_mac_min:
                                priority_min = int(pkt.stp.bridge_prio)
                                MAC_min = pkt.stp.bridge_hw
                                root_port = port.MAC

            if root_port != 'null':
                switch.set_root_port(root_port)
        else:
            if len(blocked_port) == 1:
                switch.set_root_port(blocked_port[0].MAC)

for switch in stp_monitor.switches_table:
    switch.print_port_status()
