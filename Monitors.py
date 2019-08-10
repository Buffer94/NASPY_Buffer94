from builtins import print, TimeoutError

from NetworkElements import *
from NetInterface import *
import time
import copy
import traceback

class RogueDHCPMonitor:

    def __init__(self):
        self.dhcp_servers = list()

    def update_dhcp_servers(self, packet):
        if packet.bootp.option_dhcp == '2':
            pkt_ip = packet.bootp.option_dhcp_server_id
            pkt_mac = packet.eth.src

            if len(self.dhcp_servers) > 0:
                found = False
                for dhcp_server in self.dhcp_servers:
                    if dhcp_server.equals(pkt_mac):
                        found = True
                if not found:
                    new_dhcp_server = DHCPServer(pkt_ip, pkt_mac)
                    self.dhcp_servers.append(new_dhcp_server)
                    self.print_dhcp_servers()
            else:
                new_dhcp_server = DHCPServer(pkt_ip, pkt_mac)
                self.dhcp_servers.append(new_dhcp_server)

    def print_dhcp_servers(self):
        print("I've found this DHCP Server on the network:")
        for dhcp_server in self.dhcp_servers:
            dhcp_server.print_info()


class ArpMonitor:

    def __init__(self):
        self.arp_table = list()

    def update_arp_table(self, packet):
        sender_mac = packet.arp.src_hw_mac
        sender_ip = packet.arp.src_proto_ipv4
        found = False

        if len(self.arp_table) > 0:
            for tuple in self.arp_table:
                if tuple[0] == sender_mac and tuple[1] == sender_ip:
                    found = True

            if not found:
                self.arp_table.append((sender_mac, sender_ip))
                self.find_mac_duplicate()
                self.find_ip_duplicate()
        else:
            self.arp_table.append((sender_mac, sender_ip))

    def find_mac_duplicate(self):
        mac_arp_table = dict()

        for pair in self.arp_table:
            mac = pair[0]
            ip = pair[1]
            if mac in mac_arp_table:
                if not (ip in mac_arp_table[mac]):
                    mac_arp_table[mac].append(ip)
            else:
                mac_arp_table[mac] = list()
                mac_arp_table[mac].append(ip)

        for mac in mac_arp_table:
            if len(mac_arp_table[mac]) > 1:
                print("Conflict Found, duplicate mac address: %s with this IPs: %s" % (mac, mac_arp_table[mac]))

    def find_ip_duplicate(self):
        ip_arp_table = dict()

        for pair in self.arp_table:
            mac = pair[0]
            ip = pair[1]
            if ip in ip_arp_table:
                if not (mac in ip_arp_table[ip]):
                    ip_arp_table[ip].append(mac)
            else:
                ip_arp_table[ip] = list()
                ip_arp_table[ip].append(mac)

        for ip in ip_arp_table:
            if len(ip_arp_table[ip]) > 1:
                print("Conflict Found, duplicate IP address: %s with this mac: %s" % (ip, ip_arp_table[ip]))


class VlanMonitor:

    def __init__(self):
        self.vlan_table = dict()

    def update_vlan_table(self, packet):
        sender_mac = packet.eth.src
        vlan_id = packet.vlan.id

        if vlan_id in self.vlan_table:
            if sender_mac not in self.vlan_table[vlan_id]:
                self.vlan_table[vlan_id].append(sender_mac)
        else:
            self.vlan_table[vlan_id] = list()
            self.vlan_table[vlan_id].append(sender_mac)

        self.print_present_vlan()

    def print_present_vlan(self):
        for vlan_id in self.vlan_table:
            print("Vlan: %s" % vlan_id)
            for mac in self.vlan_table[vlan_id]:
                print("mac: %s" % mac)


class STPMonitor:

    def __init__(self):
        self.switches_table = list()
        self.switch_baseline = dict()

    def update_switches_table(self, pkt):
        if pkt.highest_layer.upper() == 'STP':
            if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                for switch in self.switches_table:
                    sender_mac = pkt.eth.src
                    vlan_id = pkt.vlan.id
                    if switch.contains(sender_mac):
                        switch.get_port(sender_mac).trunk = True
                        switch.set_designated_port(sender_mac, vlan_id,
                                                   priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
            else:
                for switch in self.switches_table:
                    sender_mac = pkt.eth.src
                    vlan_id = pkt.stp.bridge_ext
                    if switch.bridge_id == pkt.stp.bridge_hw:
                        switch.set_designated_port(sender_mac, vlan_id,
                                                   priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                    else:
                        if switch.bridge_id is None and switch.contains(sender_mac):
                            switch.bridge_id = pkt.stp.bridge_hw
                            switch.set_designated_port(sender_mac, vlan_id,
                                                       priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
        else:
            if pkt.highest_layer.upper() == 'DTP':
                if pkt.dtp.tas == '0x00000001' or pkt.dtp.tos == '0x00000001':
                    for switch in self.switches_table:
                        sender_mac = pkt.eth.src
                        if switch.contains(sender_mac):
                            print("port %s is trunk" % sender_mac)
                            switch.get_port(sender_mac).trunk = True

    def discover_topology_changes(self, my_host_interface):
        net_interface = NetInterface(my_host_interface)
        net_interface.timeout = 20
        # net_interface.wait_cdp_packet()
        # net_interface.ssh_connection()

        net_interface.wait_cdp_packet()
        #####DEBUG#####
        net_interface.parameterized_ssh_connection('10.0.1.102', 'switch2', 'ciki', 'ciki', 'GigabitEthernet1/3')
        ###############

        switch_port_mac = net_interface.switch_MAC
        for switch in self.switches_table:
            if switch.contains(switch_port_mac):
                self.switch_baseline = copy.deepcopy(switch.spanning_tree_instances)
                net_interface.ssh.enable_monitor_mode_on_interface_range(switch.get_interfaces())
                tc_capture = pyshark.LiveCapture(interface=net_interface.interface)
                try:
                    tc_capture.apply_on_packets(self.tc_pkt_callback, timeout=net_interface.timeout)
                except Exception:
                    print('Capture finished!')
                bridge_id_min = dict()
                root_port = dict()
                blocked_port = dict()
                for vlan_id in switch.get_vlans():
                    bridge_id_min[vlan_id] = (60000, None)  # Priority, Mac
                    root_port[vlan_id] = None
                    blocked_port[vlan_id] = None

                print("List of blocked ports:")
                for p in self.take_blocked_port_from_baseline():
                    print(p.name)

                for port in self.take_blocked_port_from_baseline():
                    time.sleep(net_interface.timeout)
                    net_interface.parameterized_ssh_connection(switch.ip, switch.name, switch.password,
                                                               switch.en_password, switch.connected_interface, 20)
                    print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                    port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                       display_filter="stp")
                    net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                    if port.trunk:
                        rcvd_pkt = dict()
                        try:
                            port_capture.sniff(packet_count=len(switch.get_vlans()), timeout=10)
                        except TimeoutError as e:
                            print("TIMEOUT: %s" % e)
                            print('Capture on %s finished!' % port.name)
                        for pkt in port_capture:
                            if pkt.stp.bridge_ext not in port.pvlan_status:
                                switch.set_blocked_port(port.MAC, pkt.stp.bridge_ext,
                                                        priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                            if pkt.stp.bridge_ext not in rcvd_pkt and pkt.stp.bridge_hw != switch.bridge_id:
                                # print("Add %s to rcvd_pkt on port %s" % (pkt.stp.bridge_ext, port.name))
                                rcvd_pkt[pkt.stp.bridge_ext] = pkt

                        for vlan in port.get_vlan():
                            if vlan not in bridge_id_min:
                                bridge_id_min[vlan] = (60000, None)
                            if vlan not in root_port:
                                root_port[vlan] = None
                            if vlan not in blocked_port:
                                blocked_port[vlan] = None
                            # print("Port %s - vlans: %s - bridge_id_min %s - root port %s- rcvd_pkt %s:" %
                            #       (port.name, port.get_vlan(), bridge_id_min, root_port, rcvd_pkt))
                            if vlan in rcvd_pkt:
                                bridge_id_min[vlan], root_port[vlan] = self.get_min_bridge_id(rcvd_pkt[vlan],
                                                                                              bridge_id_min[vlan],
                                                                                              port.MAC, root_port[vlan])
                                if port.MAC != root_port[vlan]:
                                    blocked_port[vlan] = port.MAC
                    else:
                        try:
                            port_capture.sniff(packet_count=1, timeout=10)
                        except TimeoutError as e:
                            print("TIMEOUT: %s" % e)
                            print('Capture on %s finished!' % port.name)
                        if len(port_capture) > 0:
                            pkt = port_capture[0]
                            if pkt.stp.bridge_ext not in port.pvlan_status:
                                switch.set_blocked_port(port.MAC, pkt.stp.bridge_ext,
                                                        priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                            vlan = pkt.stp.bridge_ext
                            bridge_id_min[vlan], root_port[vlan] = self.get_min_bridge_id(pkt, bridge_id_min[vlan],
                                                                                          port.MAC, root_port[vlan])
                            if port.MAC != root_port[vlan]:
                                # print('for now %s is blocked on vlan %s' % (port.name, vlan))
                                blocked_port[vlan] = port.MAC

            for vlan_id in switch.get_vlans():
                if root_port[vlan_id] is not None:
                    for port in switch.ports:
                        if port.MAC == root_port[vlan_id]:
                            if port.pvlan_status[vlan_id] != "Root":
                                print("Port %s has switch his state on vlan %s - From %s to Root"
                                      % (port.name, vlan_id, port.pvlan_status[vlan_id]))
                                switch.set_root_port(root_port[vlan_id], vlan_id, override=True)
                        if blocked_port[vlan_id] is not None and port.MAC == blocked_port[vlan_id]:
                            if port.pvlan_status[vlan_id] != "Blocked":
                                print("Port %s has switch his state on vlan %s - From %s to Blocked"
                                      % (port.name, vlan_id, port.pvlan_status[vlan_id]))
                            switch.set_blocked_port(blocked_port[vlan_id], vlan_id, override=True)

    def tc_pkt_callback(self, pkt):
        sender_mac = pkt.eth.src
        if pkt.highest_layer.upper() == 'STP':
            pkt_bridge_id = pkt.stp.bridge_hw
            switch = self.get_switch(pkt_bridge_id)
            if switch is not None:
                port = switch.get_port(sender_mac)
                pkt_vlan_id = pkt.stp.bridge_ext
                if pkt_bridge_id == self.switch_baseline[pkt_vlan_id].bridge_id and self.port_in_baseline(port, pkt_vlan_id):
                    #PRIORITY CHANGE
                    old_prio = self.switch_baseline[pkt_vlan_id].priority
                    if int(pkt_vlan_id) + int(pkt.stp.bridge_prio) != old_prio:
                        print("Bridge (%s) priority on vlan %s is changed from %s to %s!!" % (pkt_bridge_id, pkt_vlan_id,
                                                                                              old_prio,
                                                                                              pkt.stp.bridge_prio))
                        switch.set_stp_priority(pkt_vlan_id, pkt.stp.bridge_prio)
                    #ROOT BRIDGE CHANGE
                    old_root_bridge = self.switch_baseline[pkt_vlan_id].root_bridge_id
                    pkt_root_id = pkt.stp.root_hw
                    if pkt_root_id != old_root_bridge:
                        print("Root Bridge Change! the new RB of vlan %s is %s" % (pkt_vlan_id, pkt_root_id))
                        switch.set_stp_root_id(pkt_vlan_id, pkt_root_id)
                    #PORT_STATUS_CHANGE
                    if pkt_vlan_id in port.pvlan_status:
                        port_status = port.pvlan_status[pkt_vlan_id]
                        if port_status != "Designated":
                            print("Port %s on vlan %s has switched his state from %s to Designated"
                                  % (port.name, pkt_vlan_id, port_status))
                            switch.set_designated_port(sender_mac, pkt_vlan_id, override=True)
                        for bport in self.switch_baseline[pkt_vlan_id].ports:
                            if bport.MAC == port.MAC:
                                self.switch_baseline[pkt_vlan_id].ports.remove(bport)
                    else:
                        print("New vlan (%s) has added at this trunk port %s" % (pkt_vlan_id, sender_mac))
                        switch.set_designated_port(sender_mac, pkt_vlan_id, priority=pkt.stp.root_prio, b_id=pkt_root_id)
        else:
            #NEW TRUNK PORT DISCOVER
            if pkt.highest_layer.upper() == 'DTP' and (pkt.dtp.tas == '0x00000001' or pkt.dtp.tos == '0x00000001'):
                for switch in self.switches_table:
                    if switch.contains(sender_mac) and not switch.get_port(sender_mac).trunk:
                        print("port %s is now trunk!" % sender_mac)
                        switch.get_port(sender_mac).trunk = True
                        for vlan in self.switch_baseline:
                            for port in self.switch_baseline[vlan].ports:
                                if port.MAC == sender_mac:
                                    port.trunk = True
            else:
                if pkt.highest_layer.upper() == 'DTP' and (pkt.dtp.tas == '0x00000002' or pkt.dtp.tos == '0x00000000'):
                    for switch in self.switches_table:
                        if switch.contains(sender_mac) and switch.get_port(sender_mac).trunk:
                            print("port %s is not trunk anymore!" % sender_mac)
                            switch.get_port(sender_mac).trunk = False
                            for vlan in self.switch_baseline:
                                for port in self.switch_baseline[vlan].ports:
                                    if port.MAC == sender_mac:
                                        port.trunk = False

    def take_blocked_port_from_baseline(self):
        blocked_port = list()
        for vlan in self.switch_baseline:
            for port in self.switch_baseline[vlan].ports:
                if port not in blocked_port:
                    blocked_port.append(port)
        return blocked_port

    def find_root_port(self, my_host_interface):
        timeout = 15
        net_interface = NetInterface(my_host_interface)
        net_interface.timeout = timeout
        for switch in self.switches_table:
            bridge_id_min = dict()
            root_port = dict()
            for vlan_id in switch.get_vlans():
                bridge_id_min[vlan_id] = (60000, None) #Priority, Mac
                root_port[vlan_id] = None

            for port in switch.get_blocked_port():
                print("Pre Waiting!")
                time.sleep(timeout)
                net_interface.parameterized_ssh_connection(switch.ip, switch.name, switch.password,
                                                           switch.en_password, switch.connected_interface, 20)
                print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                   display_filter="stp")
                net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                rcvd_pkt = dict()
                try:
                    port_capture.sniff(packet_count=len(switch.get_vlans()))
                except Exception as e:
                    print("TIMEOUT: %s" % e)
                    print('Capture on %s finished!' % port.name)
                for pkt in port_capture:
                    if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                        port.trunk = True
                        tagged_vlan = pkt.vlan.id
                        switch.set_blocked_port(port.MAC, tagged_vlan)
                        if pkt.stp.bridge_ext not in rcvd_pkt:
                            rcvd_pkt[pkt.stp.bridge_ext] = pkt
                        if tagged_vlan != pkt.stp.bridge_ext:
                            switch.set_blocked_port(port.MAC, pkt.stp.bridge_ext,
                                                    priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                    else:
                        vlan_id = pkt.stp.bridge_ext
                        if vlan_id not in rcvd_pkt:
                            rcvd_pkt[vlan_id] = pkt
                        switch.set_blocked_port(port.MAC, vlan_id,
                                                priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                if not port.trunk:
                    pkt = port_capture[0]
                    vlan = pkt.stp.bridge_ext
                    bridge_id_min[vlan], root_port[vlan] = self.get_min_bridge_id(pkt, bridge_id_min[vlan],
                                                                                  port.MAC, root_port[vlan])
                else:
                    for vlan in port.get_vlan():
                        if port.pvlan_status[vlan] == "Blocked":
                            if vlan not in bridge_id_min:
                                bridge_id_min[vlan] = (60000, None)
                            if vlan not in root_port:
                                root_port[vlan] = None
                            bridge_id_min[vlan], root_port[vlan] = self.get_min_bridge_id(rcvd_pkt[vlan],
                                                                                          bridge_id_min[vlan],
                                                                                          port.MAC, root_port[vlan])

            for vlan_id in switch.get_vlans():
                if root_port[vlan_id] is not None:
                    switch.set_root_port(root_port[vlan_id], vlan_id, True)

    def get_min_bridge_id(self, pkt, bridge_min_id, port_mac, root_port):
        if int(pkt.stp.bridge_prio) < bridge_min_id[0]:
            priority_min = int(pkt.stp.bridge_prio)
            mac_min = pkt.stp.bridge_hw
            bridge_min_id = (priority_min, mac_min)
            root_port = port_mac
        else:
            if bridge_min_id[1] is None:
                priority_min = int(pkt.stp.bridge_prio)
                mac_min = pkt.stp.bridge_hw
                bridge_min_id = (priority_min, mac_min)
                root_port = port_mac
            else:
                if int(pkt.stp.bridge_prio) == bridge_min_id[0]:
                    raw_mac_min = ''
                    raw_mac_curr = ''
                    mac_parts_min = bridge_min_id[1].split(':')
                    for part in mac_parts_min:
                        raw_mac_min += part
                    mac_parts_curr = pkt.stp.bridge_hw.split(':')
                    for part in mac_parts_curr:
                        raw_mac_curr += part

                    int_mac_min = int(raw_mac_min, 16)
                    int_mac_curr = int(raw_mac_curr, 16)

                    if int_mac_curr < int_mac_min:
                        priority_min = int(pkt.stp.bridge_prio)
                        mac_min = pkt.stp.bridge_hw
                        bridge_min_id = (priority_min, mac_min)
                        root_port = port_mac
        return bridge_min_id, root_port

    def set_connected_interface_status(self, my_host_interface):
        print("Check connected interface status")
        timeout = 10
        for switch in self.switches_table:
            port_capture = pyshark.LiveCapture(interface=my_host_interface, display_filter="stp")
            port_capture.sniff(packet_count=1, timeout=timeout)
            pkt = port_capture[0]
            vlan = pkt.stp.bridge_ext
            port_mac = pkt.eth.src
            switch.set_designated_port(port_mac, vlan)

    def add_switch(self, switch):
        if switch not in self.switches_table:
            self.switches_table.append(switch)

    def print_switches_status(self):
        for switch in self.switches_table:
            print("\nSwitch %s:" % switch.name)
            switch.print_spanning_tree()

    def get_switch(self, switch_id):
        for switch in self.switches_table:
            if switch.bridge_id == switch_id:
                return switch
        return None

    def port_in_baseline(self, port, vlan_id):
        for p in self.switch_baseline[vlan_id].ports:
            if port.MAC == p.MAC:
                return True
        return False
