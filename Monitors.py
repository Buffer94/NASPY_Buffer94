from NetworkElements import *
from NetInterface import *
import time
import copy
import concurrent


class RogueDHCPMonitor:

    def __init__(self):
        self.dhcp_servers = list()

    def update_dhcp_servers(self, pkt):
        if pkt.bootp.option_dhcp == '2':
            pkt_ip = pkt.bootp.option_dhcp_server_id
            pkt_mac = pkt.eth.src

            if 'option_subnet_mask' in pkt.bootp.field_names:
                subnet = pkt.bootp.option_subnet_mask
            else:
                subnet = '0.0.0.0'

            if len(self.dhcp_servers) > 0:
                found = False
                for dhcp_server in self.dhcp_servers:
                    if dhcp_server.equals(pkt_mac):
                        found = True
                if not found:
                    new_dhcp_server = DHCPServer(pkt_ip, pkt_mac, subnet)
                    self.dhcp_servers.append(new_dhcp_server)
                    print("New DHCP Server discovered")
                    new_dhcp_server.print_info()
            else:
                new_dhcp_server = DHCPServer(pkt_ip, pkt_mac, subnet)
                print("New DHCP Server discovered")
                new_dhcp_server.print_info()
                self.dhcp_servers.append(new_dhcp_server)

    def print_dhcp_servers(self):
        if len(self.dhcp_servers) > 0:
            print("I've found this DHCP Servers on the network:")
            for dhcp_server in self.dhcp_servers:
                dhcp_server.print_info()
        else:
            print("No DHCP Servers found!")


class RogueDNSMonitor:

    def __init__(self):
        self.dns_servers = list()

    def update_dns_servers(self, pkt):
        if pkt.dns.flags_response == '1':
            server_ip = pkt.ip.src
            server_mac = pkt.eth.src

            if len(self.dns_servers) > 1:
                for dns_server in self.dns_servers:
                    if dns_server.equals(server_mac):
                        found = True
                if not found:
                    new_dns_server = DNSServer(server_ip, server_mac)
                    self.dns_servers.append(new_dns_server)
                    print("New DNS Server Discovered")
                    new_dns_server.print_info()
            else:
                new_dns_server = DNSServer(server_ip, server_mac)
                self.dns_servers.append(new_dns_server)
                print("New DNS Server Discovered")
                new_dns_server.print_info()

    def print_dns_servers(self):
        if len(self.dns_servers) > 0:
            print("I've found this DHCP Servers on the network:")
            for dns_server in self.dns_servers:
                dns_server.print_info()
        else:
            print("No DNS Servers found!")


class ArpMonitor:

    def __init__(self):
        self.ip_arp_table = dict()
        self.mac_arp_table = dict()

    def update_arp_table(self, pkt, sender_port=None, target_port=None):
        sender_mac = pkt.arp.src_hw_mac
        sender_ip = pkt.arp.src_proto_ipv4
        target_mac = pkt.arp.dst_hw_mac
        target_ip = pkt.arp.dst_proto_ipv4

        sender_vlan_id = 1
        target_vlan_id = 1

        if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
            sender_vlan_id = pkt.vlan.id
            target_vlan_id = pkt.vlan.id
        else:
            if sender_port is not None:
                if not sender_port.trunk:
                    sender_vlan_id = sender_port.pvlan_status[0]
                    print("Sender port %s - vlan: %s" % (sender_port.MAC, sender_vlan_id))

            if target_port is not None:
                if not target_port.trunk:
                    target_vlan_id = target_port.pvlan_status[0]
                    print("Sender port %s - vlan: %s" % (target_port.MAC, target_vlan_id))

        if target_mac != '00:00:00:00:00:00' and target_mac != 'ff:ff:ff:ff:ff:ff' and target_ip != '0.0.0.0':
            self.add_entry(target_ip, target_mac, target_vlan_id)

        self.add_entry(sender_ip, sender_mac, sender_vlan_id)

    def add_entry(self, ip, mac, vlan_id):
        if ip in self.ip_arp_table:
            if not ((mac, vlan_id) in self.ip_arp_table[ip]):
                self.ip_arp_table[ip].append((mac, vlan_id))
                if len(self.ip_arp_table[ip]) > 1:
                    self.check_ip_duplicate()
        else:
            self.ip_arp_table[ip] = list()
            self.ip_arp_table[ip].append((mac, vlan_id))

        if mac in self.mac_arp_table:
            if not ((ip, vlan_id) in self.mac_arp_table[mac]):
                self.mac_arp_table[mac].append((ip, vlan_id))
                if len(self.mac_arp_table[mac]) > 1:
                    self.check_mac_duplicate()
        else:
            self.mac_arp_table[mac] = list()
            self.mac_arp_table[mac].append((ip, vlan_id))

    def check_ip_duplicate(self):
        macs = dict()
        for ip in self.ip_arp_table:
            for pair in self.ip_arp_table[ip]:
                for pair2 in self.ip_arp_table[ip]:
                    if pair[0] != pair2[0] and pair[1] == pair2[1]:
                        if ip in macs:
                            if pair not in macs[ip]:
                                macs[ip].append(pair)
                            if pair2 not in macs[ip]:
                                macs[ip].append(pair2)
                        else:
                            macs[ip] = list()
                            macs[ip].append(pair)
                            macs[ip].append(pair2)

        for ip in macs:
            if len(macs[ip]) > 1:
                print("Conflict Found, duplicate IP address: %s with this MACs: %s" % (ip, str(macs[ip])[1:-1]))

    def check_mac_duplicate(self):
        ips = dict()
        for mac in self.mac_arp_table:
            for pair in self.mac_arp_table[mac]:
                for pair2 in self.mac_arp_table[mac]:
                    if pair[0] != pair2[0] and pair[1] == pair2[1]:
                        if mac in ips:
                            if pair not in ips:
                                ips[mac].append(pair)
                            if pair2 not in ips:
                                ips[mac].append(pair2)
                        else:
                            ips[mac] = list()
                            ips[mac].append(pair)
                            ips[mac].append(pair2)

        for mac in ips:
            if len(ips[mac]) > 1:
                print("Conflict Found, duplicate MAC address: %s with this IPs: %s" % (mac, str(ips[mac])[1:-1]))

    def print_ip_arp_table(self):
        print("Arp Table:")
        for ip in self.ip_arp_table:
            print("IP %s - MAC: %s" % (ip, str(self.ip_arp_table[ip])[1:-1]))

    def print_mac_arp_table(self):
        for mac in self.mac_arp_table:
            print("MAC: %s - IP: %s" % (mac, str(self.mac_arp_table[mac])[1:-1]))


class STPMonitor:

    def __init__(self):
        self.switches_table = list()
        self.switch_baseline = dict()
        self.waiting_timer = 0

    def update_switches_table(self, pkt):
        if pkt.highest_layer.upper() == 'STP':
            if self.waiting_timer < (int(pkt.stp.forward) + int(pkt.stp.max_age)):
                self.waiting_timer = (int(pkt.stp.forward) + int(pkt.stp.max_age))

            if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                for switch in self.switches_table:
                    sender_mac = pkt.eth.src
                    vlan_id = pkt.vlan.id
                    if switch.contains(sender_mac):
                        switch.get_port(sender_mac).trunk = True
                        switch.set_designated_port(sender_mac, vlan_id,
                                                   priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
            else:
                found = False
                for switch in self.switches_table:
                    sender_mac = pkt.eth.src
                    vlan_id = pkt.stp.bridge_ext
                    if switch.bridge_id == pkt.stp.bridge_hw:
                        switch.set_designated_port(sender_mac, vlan_id,
                                                   priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                        found = True
                    else:
                        if switch.bridge_id is None and switch.contains(sender_mac):
                            switch.bridge_id = pkt.stp.bridge_hw
                            switch.set_designated_port(sender_mac, vlan_id,
                                                       priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                            found = True

                if not found:
                    switch = Switch(pkt.stp.bridge_hw, None, None, None, None)
                    vlan_id = pkt.stp.bridge_ext
                    bridge_id = pkt.stp.bridge_hw
                    priority = pkt.stp.bridge_prio
                    port = Port(pkt.eth.src, pkt.eth.src)
                    switch.add_ports(port)
                    switch.set_designated_port(port.MAC, vlan_id, priority=priority, b_id=bridge_id)
                    switch.set_stp_root_id(vlan_id, pkt.stp.root_hw)
                    self.switches_table.append(switch)

        else:
            if pkt.highest_layer.upper() == 'DTP':
                if pkt.dtp.tas == '0x00000001' or pkt.dtp.tos == '0x00000001':
                    for switch in self.switches_table:
                        sender_mac = pkt.eth.src
                        if switch.contains(sender_mac):
                            print("port %s is trunk" % sender_mac)
                            switch.get_port(sender_mac).trunk = True

    def discover_topology_changes(self, my_host_interface, password):
        net_interface = NetInterface(my_host_interface, password)
        net_interface.timeout = 35
        net_interface.wait_cdp_packet()
        net_interface.ssh_no_credential_connection()
        switch_port_mac = net_interface.switch_MAC
        for switch in self.switches_table:
            if switch.contains(switch_port_mac):
                self.switch_baseline = copy.deepcopy(switch.spanning_tree_instances)
                if switch.connected_interface is not None:
                    net_interface.ssh.enable_monitor_mode_on_interface_range(switch.get_interfaces())
                tc_capture = pyshark.LiveCapture(interface=net_interface.interface)
                try:
                    tc_capture.apply_on_packets(self.tc_pkt_callback, timeout=net_interface.timeout)
                except concurrent.futures.TimeoutError:
                    print('Capture finished!')
                bridge_id_min = dict()
                root_port = dict()
                blocked_port = dict()
                for vlan_id in switch.get_vlans():
                    bridge_id_min[vlan_id] = (60000, None)  # Priority, Mac
                    root_port[vlan_id] = None
                    blocked_port[vlan_id] = None

                if switch.connected_interface is not None:
                    for port in self.take_blocked_port_from_baseline():
                        print("Waiting...")
                        time.sleep(net_interface.timeout)
                        net_interface.parameterized_ssh_connection(switch.ip, switch.name, switch.password,
                                                                   switch.en_password, switch.connected_interface, 20)
                        print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                        port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                           display_filter="stp")
                        net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                        if port.trunk:
                            rcvd_pkt = dict()
                            port_capture.sniff(packet_count=len(switch.get_vlans()), timeout=10)
                            for pkt in port_capture:
                                if pkt.stp.bridge_ext not in port.pvlan_status:
                                    switch.set_blocked_port(port.MAC, pkt.stp.bridge_ext,
                                                            priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                                if pkt.stp.bridge_ext not in rcvd_pkt and pkt.stp.bridge_hw != switch.bridge_id:
                                    rcvd_pkt[pkt.stp.bridge_ext] = pkt

                            for vlan in port.get_vlan():
                                if vlan not in bridge_id_min:
                                    bridge_id_min[vlan] = (60000, None)
                                if vlan not in root_port:
                                    root_port[vlan] = None
                                if vlan not in blocked_port:
                                    blocked_port[vlan] = None
                                if vlan in rcvd_pkt:
                                    bridge_id_min[vlan], root_port[vlan], blocked_port[vlan] = self.get_min_bridge_id(rcvd_pkt[vlan], bridge_id_min[vlan],
                                                                                                                      port.MAC, root_port[vlan], blocked_port[vlan])
                        else:
                            port_capture.sniff(packet_count=1, timeout=10)
                            if len(port_capture) > 0:
                                pkt = port_capture[0]
                                if pkt.stp.bridge_ext not in port.pvlan_status:
                                    switch.set_blocked_port(port.MAC, pkt.stp.bridge_ext,
                                                            priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                                vlan = pkt.stp.bridge_ext
                                bridge_id_min[vlan], root_port[vlan], blocked_port[vlan] = self.get_min_bridge_id(pkt, bridge_id_min[vlan], port.MAC,
                                                                                                                  root_port[vlan], blocked_port[vlan])
            if switch.connected_interface is not None:
                for vlan_id in switch.get_vlans():
                    if root_port[vlan_id] is not None:
                        for port in switch.ports:
                            if port.MAC == root_port[vlan_id]:
                                if port.pvlan_status[vlan_id] != "Root":
                                    print("Port %s has switch his state on vlan %s - From %s to Root"
                                          % (port.name, vlan_id, port.pvlan_status[vlan_id]))
                                    switch.increase_port_tc_counter(vlan_id, port.MAC)
                                    switch.set_root_port(root_port[vlan_id], vlan_id, override=True)
                            else:
                                if blocked_port[vlan_id] is not None and port.MAC == blocked_port[vlan_id]:
                                    if port.pvlan_status[vlan_id] != "Blocked":
                                        print("Port %s has switch his state on vlan %s - From %s to Blocked"
                                              % (port.name, vlan_id, port.pvlan_status[vlan_id]))
                                        switch.increase_port_tc_counter(vlan_id, port.MAC)
                                    switch.set_blocked_port(blocked_port[vlan_id], vlan_id, override=True)
                                else:
                                    if vlan_id in port.pvlan_status and self.port_in_baseline(port, vlan_id):
                                        port.remove_vlan(vlan_id)
                                        switch.remove_port_from_stp(vlan_id, port)

    def tc_pkt_callback(self, pkt):
        sender_mac = pkt.eth.src
        if pkt.highest_layer.upper() == 'STP':
            pkt_bridge_id = pkt.stp.bridge_hw
            switch = self.get_switch(pkt_bridge_id)
            if switch is not None:
                port = switch.get_port(sender_mac)
                pkt_vlan_id = pkt.stp.bridge_ext
                pkt_root_id = pkt.stp.root_hw
                if pkt_bridge_id == self.switch_baseline[pkt_vlan_id].bridge_id:
                    if self.port_in_baseline(port, pkt_vlan_id):
                        #PRIORITY CHANGE
                        old_prio = self.switch_baseline[pkt_vlan_id].priority
                        tc_change = False
                        if int(pkt_vlan_id) + int(pkt.stp.bridge_prio) != old_prio:
                            print("Bridge (%s) priority on vlan %s is changed from %s to %s!!" % (pkt_bridge_id, pkt_vlan_id,
                                                                                                  old_prio,
                                                                                                  pkt.stp.bridge_prio))
                            switch.set_stp_priority(pkt_vlan_id, pkt.stp.bridge_prio)
                            self.switch_baseline[pkt_vlan_id].priority = int(pkt.stp.bridge_prio) + int(pkt_vlan_id)
                            tc_change = True
                        #ROOT BRIDGE CHANGE
                        old_root_bridge = self.switch_baseline[pkt_vlan_id].root_bridge_id
                        if pkt_root_id != old_root_bridge:
                            print("Root Bridge Change! the new RB of vlan %s is %s" % (pkt_vlan_id, pkt_root_id))
                            switch.set_stp_root_id(pkt_vlan_id, pkt_root_id)
                            self.switch_baseline[pkt_vlan_id].root_bridge_id = pkt_root_id
                            tc_change = True
                        #PORT_STATUS_CHANGE
                        if pkt_vlan_id in port.pvlan_status:
                            port_status = port.pvlan_status[pkt_vlan_id]
                            if port_status != "Designated":
                                print("Port %s on vlan %s has switched his state from %s to Designated"
                                      % (port.name, pkt_vlan_id, port_status))
                                switch.set_designated_port(sender_mac, pkt_vlan_id, override=True)
                                switch.increase_port_tc_counter(pkt_vlan_id, sender_mac)
                            for bport in self.switch_baseline[pkt_vlan_id].ports:
                                if bport.MAC == port.MAC:
                                    self.switch_baseline[pkt_vlan_id].ports.remove(bport)

                        if tc_change:
                            switch.increase_tc_counter(pkt_vlan_id)
                    else:
                        if pkt_vlan_id not in port.pvlan_status:
                            print("New vlan (%s) has added at this trunk port %s" % (pkt_vlan_id, port.name))
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
            if switch.connected_interface is not None:
                bridge_id_min = dict()
                root_port = dict()
                for vlan_id in switch.get_vlans():
                    bridge_id_min[vlan_id] = (60000, None) #Priority, Mac
                    root_port[vlan_id] = None

                for port in switch.get_blocked_port():
                    print("Waiting...")
                    time.sleep(timeout)
                    net_interface.parameterized_ssh_connection(switch.ip, switch.name, switch.password,
                                                               switch.en_password, switch.connected_interface, 20)
                    print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                    port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                       display_filter="stp")
                    net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                    rcvd_pkt = dict()
                    port_capture.sniff(packet_count=len(switch.get_vlans()))
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

    @staticmethod
    def get_min_bridge_id(pkt, bridge_min_id, port_mac, root_port, blocked_port=0):
        if int(pkt.stp.bridge_prio) < bridge_min_id[0]:
            priority_min = int(pkt.stp.bridge_prio)
            mac_min = pkt.stp.bridge_hw
            bridge_min_id = (priority_min, mac_min)
            if blocked_port != 0 and root_port is not None:
                blocked_port = root_port
            root_port = port_mac
        else:
            if bridge_min_id[1] is None:
                priority_min = int(pkt.stp.bridge_prio)
                mac_min = pkt.stp.bridge_hw
                bridge_min_id = (priority_min, mac_min)
                if blocked_port != 0  and root_port is not None:
                    blocked_port = root_port
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
                        if blocked_port != 0  and root_port is not None:
                            blocked_port = root_port
                        root_port = port_mac
                    else:
                        if blocked_port != 0:
                            blocked_port = port_mac
                else:
                    if blocked_port != 0:
                        blocked_port = port_mac

        return (bridge_min_id, root_port) if (blocked_port == 0) else (bridge_min_id, root_port, blocked_port)

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
            switch.print_trunk_ports()

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
