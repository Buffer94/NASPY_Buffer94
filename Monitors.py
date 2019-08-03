from builtins import print

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
        self.switch_table_TC = dict()

    def update_switches_table(self, pkt):
        if pkt.highest_layer.upper() == 'STP':
            if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                for switch in self.switches_table:
                    sender_mac = pkt.eth.src
                    vlan_id = pkt.vlan.id
                    if switch.contains(sender_mac):
                        print("port %s is trunk" % sender_mac)
                        switch.get_port(sender_mac).trunk = True
                        switch.set_designated_port(sender_mac, vlan_id, pkt.stp.bridge_prio, pkt.stp.bridge_hw)
            else:
                for switch in self.switches_table:
                    sender_mac = pkt.eth.src
                    vlan_id = pkt.stp.bridge_ext
                    if switch.bridge_id == pkt.stp.bridge_hw:
                        switch.set_designated_port(sender_mac, vlan_id, pkt.stp.bridge_prio, pkt.stp.bridge_hw)
                    else:
                        if switch.bridge_id is None and switch.contains(sender_mac):
                            switch.bridge_id = pkt.stp.bridge_hw
                            switch.set_designated_port(sender_mac, vlan_id, pkt.stp.bridge_prio, pkt.stp.bridge_hw)
        # else:
        #     if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
        #         for switch in self.switches_table:
        #             sender_mac = pkt.eth.src
        #             vlan_id = pkt.vlan.id
        #             if switch.contains(sender_mac):
        #                 print("port %s is TRUUUUUUUUUUUUUUUUUUUUUUUUUUNK" % sender_mac)
        #                 switch.get_port(sender_mac).trunk = True
        #                 switch.set_designated_port(sender_mac, vlan_id, pkt.stp.bridge_prio, pkt.stp.bridge_hw)


    def discover_topology_changes(self, my_host_interface):
        net_interface = NetInterface(my_host_interface)
        net_interface.timeout = 20
        net_interface.wait_cdp_packet()
        net_interface.ssh_connection()
        # net_interface.ssh_no_credential_connection()
        self.parse_switch_table_for_topology_change()

        for switch_tmp in self.switch_table_TC:
            sw = self.get_switch(switch_tmp)
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
                                if port.MAC == self.switch_table_TC[switch_tmp][0] \
                                        and (port.status == 'Blocked' or port.status == 'Designated'):
                                    print("Port %s has switched his state from % to Root" % (port.name, port.status))
                                    self.switch_table_TC[switch_tmp].remove(port.MAC)
                                    port.set_port_as_root()
                else:
                    switch = self.get_switch(switch_tmp)
                    if switch is not None:
                        timeout = 10
                        bridge_id_min = (60000, None)  # Priority, Mac
                        root_port = None
                        blocked_port = self.switch_table_TC[switch_tmp]
                        net_interface_port = NetInterface(my_host_interface)
                        net_interface_port.timeout = timeout
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
                                pkt = port_capture[0]
                                bridge_id_min, root_port = self.get_min_bridge_id(pkt, bridge_id_min, switch.get_port(port).MAC, root_port)
                            except Exception:
                                print('Capture on %s finished!' % switch.get_port(port).name)

                        if root_port is not None:
                            for port in switch.ports:
                                for p in blocked_port:
                                    if port.MAC == root_port:
                                        if port.MAC == p and (port.status == 'Designated' or port.status == 'Blocked'):
                                            print("Port %s has switched his state from %s to Root"
                                                  % (port.name, port.status))
                                            switch.set_root_port(root_port)
                                            self.switch_table_TC[switch_tmp].remove(p)
                                    else:
                                        if port.MAC == p and (port.status == 'Designated' or port.status == 'Root'):
                                            print("Port %s has switched his state from %s to Blocked"
                                                  % (port.name, port.status))
                                            switch.set_blocked_port(port.MAC)
                                            self.switch_table_TC[switch_tmp].remove(p)
                    else:
                        print("Switch is none!")

    def parse_switch_table_for_topology_change(self):
        for switch in self.switches_table:
            if switch.bridge_id not in self.switch_table_TC:
                self.switch_table_TC[switch.bridge_id] = list()
                for port in switch.ports:
                    if port.name != switch.connected_interface:
                        self.switch_table_TC[switch.bridge_id].append(port.MAC)
            else:
                for port in switch.ports:
                    if port.MAC not in self.switch_table_TC[switch.bridge_id] and port.name != switch.connected_interface:
                        self.switch_table_TC[switch.bridge_id].append(port.MAC)

    def topology_change_pkt_callback(self, packet):
        sender_mac = packet.eth.src
        packet_bridge_id = packet.stp.bridge_hw

        if packet_bridge_id in self.switch_table_TC and sender_mac in self.switch_table_TC[packet_bridge_id]:
            self.switch_table_TC[packet_bridge_id].remove(sender_mac)
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
        net_interface.timeout = timeout
        for switch in self.switches_table:
            bridge_id_min = dict()
            root_port = dict()
            for vlan_id in switch.vlans:
                bridge_id_min[vlan_id] = (60000, None) #Priority, Mac
                root_port[vlan_id] = None

            blocked_port = switch.get_blocked_port()
            for port in blocked_port:
                time.sleep(timeout * 2)
                net_interface.parameterized_ssh_connection(switch.ip, switch.name, switch.password,
                                                           switch.en_password, switch.connected_interface, 20)
                print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                   display_filter="stp && stp.bridge.hw != %s"
                                                                  % switch.bridge_id)
                net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                rcvd_pkt = dict()
                try:
                    print("Pre sniff")
                    # port_capture.sniff_continuously(packet_count=2)
                    # port_capture.sniff(packet_count=2, timeout=10)
                    port_capture.load_packets(2, 10)
                    print("post sniff")
                except TimeoutError as e:
                    print("TIMEOUT: %s" % e)
                    print('Capture on %s finished!' % port.name)

                for pkt in port_capture:
                    print("Miao")
                    if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                        port.trunk = True
                        tagged_vlan = pkt.vlan.id
                        switch.set_blocked_port(port.MAC, tagged_vlan)
                        print("Vlan %s" % pkt.stp.bridge_ext)
                        if pkt.stp.bridge_ext not in rcvd_pkt:
                           print("Vlan %s added" % pkt.stp.bridge_ext)
                           rcvd_pkt[pkt.stp.bridge_ext] = pkt
                        if tagged_vlan != pkt.stp.bridge_ext:
                            switch.set_blocked_port(port.MAC, pkt.stp.bridge_ext)
                    else:
                        vlan_id = pkt.stp.bridge_ext
                        print("Vlan %s" % vlan_id)
                        if vlan_id not in rcvd_pkt:
                            print("Vlan %s added" % vlan_id)
                            rcvd_pkt[vlan_id] = pkt
                        switch.set_blocked_port(port.MAC, vlan_id)
                print("per qualche motivo sono qui?")
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
                                root_port[vlan_id] = None
                            bridge_id_min[vlan], root_port[vlan] = self.get_min_bridge_id(rcvd_pkt[vlan], bridge_id_min[vlan],
                                                                                          port.MAC, root_port[vlan])

            for vlan_id in switch.vlans:
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
                    raw_mac_min = None
                    raw_mac_curr = None
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

    def set_root_port(self, bridge_hw, port_mac):
        print(">>>>>DEBUG<<<<<I want to set %s as root port of %s" %(bridge_hw, port_mac))
        for switch in self.switches_table:
            if switch.bridge_id == bridge_hw:
                switch.set_root_port(port_mac)

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
