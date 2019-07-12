from NetworkElements import *
from NetInterface import *
import time


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
            for pair in self.arp_table:
                if pair[0] == sender_mac and pair[1] == sender_ip:
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
        self.switch_table_temp = dict()

    def update_switches_table(self, packet):
        for switch in self.switches_table:
            if packet.highest_layer.upper() == 'STP':
                sender_mac = packet.eth.src
                if switch.bridge_id == packet.stp.bridge_hw:
                    switch.set_designated_port(sender_mac)
                else:
                    if switch.bridge_id == '' and switch.contains(sender_mac):
                        switch.bridge_id = packet.stp.bridge_hw
                        switch.bridge_priority = packet.stp.bridge_prio
                        if packet.stp.root_hw == packet.stp.bridge_hw:
                            switch.is_root_bridge = True
                        else:
                            switch.is_root_bridge = False
                        switch.set_designated_port(sender_mac)

    def discover_topology_changes(self, my_host_interface):
        net_interface = NetInterface(my_host_interface)
        net_interface.timeout = 20
        net_interface.wait_cdp_packet()
        net_interface.ssh_connection()
        self.parse_switch_table_for_topology_change()

        for switch_tmp in self.switch_table_temp:
            sw = self.get_specific_switch(switch_tmp)
            switch_interfaces = sw.get_interfaces()
            switch_interfaces.remove(sw.connected_interface)
            net_interface.ssh.enable_monitor_mode_on_interface_range(switch_interfaces)
            net_interface.capture = pyshark.LiveCapture(interface=net_interface.interface, display_filter="stp")
            try:
                net_interface.capture.apply_on_packets(self.topology_change_pkt_callback, timeout=net_interface.timeout)
            except Exception:
                print('Capture finished!')
            if len(switch_tmp) > 0:
                if len(switch_tmp) == 1:
                    for switch in self.switches_table:
                        if switch.bridge_id == switch_tmp:
                            for port in switch:
                                if port.MAC == self.switch_table_temp[switch_tmp][0] \
                                        and (port.status == 'Blocked' or port.status == 'Designated'):
                                    print("Port %s has switched his state from % to Root" % (port.name, port.status))
                                    self.switch_table_temp[switch_tmp].remove(port.MAC)
                                    port.set_port_as_root()
                else:
                    switch = self.get_specific_switch(switch_tmp)
                    if switch is not None:
                        priority_min = 60000
                        timeout = 10
                        MAC_min = 'null'
                        root_port = 'null'
                        blocked_port = self.switch_table_temp[switch_tmp]
                        net_interface_port = NetInterface(my_host_interface)
                        net_interface_port.timeout = 20
                        for port in blocked_port:
                            time.sleep(timeout * 2)
                            net_interface_port.parameterized_ssh_connection(switch.ip, switch.name, switch.password,
                                                                            switch.en_password, switch.connected_interface,
                                                                            20)
                            print('start sniffing on %s...' % port)
                            port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                               display_filter="stp && stp.bridge.hw != %s" % switch.bridge_id)
                            net_interface_port.ssh.enable_monitor_mode_on_specific_port(switch.get_port(port).name)
                            try:
                                port_capture.sniff(packet_count=1, timeout=timeout)
                            except Exception:
                                print('Capture on %s finished!' % port.name)
                            pkt = port_capture[0]
                            if int(pkt.stp.bridge_prio) < priority_min:
                                priority_min = int(pkt.stp.bridge_prio)
                                MAC_min = pkt.stp.bridge_hw
                                root_port = switch.get_port(port).MAC
                            else:
                                if MAC_min == 'null':
                                    priority_min = int(pkt.stp.bridge_prio)
                                    MAC_min = pkt.stp.bridge_hw
                                    root_port = switch.get_port(port).MAC
                                else:
                                    if int(pkt.stp.bridge_prio) == priority_min:
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
                                            root_port = switch.get_port(port).MAC

                        if root_port != 'null':
                            for port in switch.ports:
                                for p in blocked_port:
                                    if port.MAC == root_port:
                                        if port.MAC == p and (port.status == 'Designated' or port.status == 'Blocked'):
                                            print(
                                                "Port %s has switched his state from %s to Root" % (port.name, port.status))
                                            switch.set_root_port(root_port)
                                            self.switch_table_temp[switch_tmp].remove(p)
                                    else:
                                        if port.MAC == p and (port.status == 'Designated' or port.status == 'Root'):
                                            print("Port %s has switched his state from %s to Blocked"
                                                  % (port.name, port.status))
                                            switch.set_blocked_port(port.MAC)
                                            self.switch_table_temp[switch_tmp].remove(p)
                    else:
                        print("Switch is none!")

    def parse_switch_table_for_topology_change(self):
        for switch in self.switches_table:
            if not switch.bridge_id in self.switch_table_temp:
                self.switch_table_temp[switch.bridge_id] = list()
                for port in switch.ports:
                    if port.name != switch.connected_interface:
                        self.switch_table_temp[switch.bridge_id].append(port.MAC)
            else:
                for port in switch.ports:
                    if port.MAC not in self.switch_table_temp[switch.bridge_id] and port.name != switch.connected_interface:
                        self.switch_table_temp[switch.bridge_id].append(port.MAC)

    def topology_change_pkt_callback(self, packet):
        sender_mac = packet.eth.src
        packet_bridge_id = packet.stp.bridge_hw

        if packet_bridge_id in self.switch_table_temp and sender_mac in self.switch_table_temp[packet_bridge_id]:
            self.switch_table_temp[packet_bridge_id].remove(sender_mac)
            for switch in self.switches_table:
                if switch.bridge_id == packet_bridge_id:
                    if switch.bridge_priority != packet.stp.bridge_prio:
                        print("Bridge priority is changed!! from %s to %s" % (switch.bridge_priority, packet.stp.bridge_prio))
                        switch.bridge_priority = packet.stp.bridge_prio
                    if packet.stp.root_hw == switch.bridge_id and not switch.is_root_bridge:
                        print("Topology Change! not this switch (%s) is the Root Bridge!" % switch.bridge_id)
                        switch.is_root_bridge = True
                    for port in switch.ports:
                        if port.MAC == sender_mac:
                            if packet.stp.type == '0x80' or packet.stp.type == '0x80000000':
                                if port.status == 'Blocked' or port.status == 'Designated':
                                    print("Port %s has switched his state from % to Root" % (port.name, port.status))
                                    port.set_port_as_root()
                            else:
                                if port.status == 'Blocked' or port.status == 'Root':
                                    print("Port %s has switched his state from % to Designated"
                                          % (port.name, port.status))
                                    port.set_port_as_designated()

    def find_root_port(self, my_host_interface):
        timeout = 10
        net_interface = NetInterface(my_host_interface)
        for switch in self.switches_table:
            priority_min = 60000
            MAC_min = 'null'
            root_port = 'null'
            if not switch.there_is_root_port():
                blocked_port = switch.get_blocked_port()
                if len(blocked_port) > 1:
                    for port in blocked_port:
                        time.sleep(timeout * 2)
                        net_interface.parameterized_ssh_connection(switch.ip, switch.name, switch.password,
                                                                   switch.en_password, switch.connected_interface, 20)
                        print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                        port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                           display_filter="stp && stp.bridge.hw != %s" % switch.bridge_id)
                        net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                        try:
                            port_capture.sniff(packet_count=1, timeout=timeout)
                        except Exception:
                            print('Capture on %s finished!' % port.name)
                        pkt = port_capture[0]
                        if int(pkt.stp.bridge_prio) < priority_min:
                            priority_min = int(pkt.stp.bridge_prio)
                            MAC_min = pkt.stp.bridge_hw
                            root_port = port.MAC
                        else:
                            if MAC_min == 'null':
                                priority_min = int(pkt.stp.bridge_prio)
                                MAC_min = pkt.stp.bridge_hw
                                root_port = port.MAC
                            else:
                                if int(pkt.stp.bridge_prio) == priority_min:
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
                        print("I want to set %s as root port" % blocked_port[0].name)
                        switch.set_root_port(blocked_port[0].MAC)

    def set_root_port(self, bridge_hw, port_mac):
        print(">>>>>DEBUG<<<<<I want to set %s as root port of %s" %(bridge_hw, port_mac))
        for switch in self.switches_table:
            if switch.bridge_id == bridge_hw:
                switch.set_root_port(port_mac)

    def add_switch(self, switch):
        if switch not in self.switches_table:
            self.switches_table.append(switch)

    def print_switches_status(self):
        for switch in self.switches_table:
            switch.print_port_status()

    def get_specific_switch(self, switch_id):
        for switch in self.switches_table:
            if switch.bridge_id == switch_id:
                return switch
        return None
