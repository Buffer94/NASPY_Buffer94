from NetworkElements import *


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

    def update_switches_table(self, packet):
        print("Updating Switches Table..")
        sender_mac = packet.eth.src
        for switch in self.switches_table:
            if switch.bridge_id == packet.stp.bridge_hw:
                sender_mac = packet.eth.src
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
            switch.print_port_status()

    def add_switch(self, switch):
        if switch not in self.switches_table:
            self.switches_table.append(switch)

    def print_switches_status(self):
        for switch in self.switches_table:
            switch.print_port_status()

    def discover_topology_change(self):
        print('')
        # TODO
