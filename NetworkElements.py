class DHCPServer:

    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address

    def print_info(self):
        print('Ip Address: %s MAC address: %s' % (self.ip_address, self.mac_address))

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def equals(self, n_mac_address):
        if self.mac_address == n_mac_address:
            return True
        return False


class Switch:

    def __init__(self, n, ip, pwd, en_pwd, conn_interface):
        self.name = n
        self.bridge_id = None
        self.bridge_priority = 0
        self.is_root_bridge = True
        self.ports = list()
        self.ip = ip
        self.password = pwd
        self.en_password = en_pwd
        self.connected_interface = conn_interface
        self.spanning_tree_instances = dict()
        self.vlans = list()

    def set_bridge_info(self, b_id, b_p, rb):
        self.bridge_id = b_id
        self.bridge_priority = b_p
        self.is_root_bridge = rb

    def get_interfaces(self):
        interfaces = list()
        for port in self.ports:
            interfaces.append(port.name)
        return interfaces

    def add_ports(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def set_designated_port(self, port_address, vlan_id):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port)
                port.set_port_as_designated()

    def set_blocked_port(self, port_address, vlan_id):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port)
                port.set_port_as_blocked()

    def set_root_port(self, port_address, vlan_id):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port)
                port.set_port_as_root()

    def print_port_status(self):
        for port in self.ports:
            print("Port: %s - Address: %s, Status: %s" % (port.name, port.MAC, port.status))

    def print_spanning_tree(self):
        for vlan_id in self.spanning_tree_instances:
            print("Spanning Tree on Vlan: %s" % vlan_id)
            for port in self.spanning_tree_instances[vlan_id]:
                print("Port: %s - Address: %s, Status: %s" % (port.name, port.MAC, port.status))

    def get_port(self, port_mac):
        for port in self.ports:
            if port.MAC == port_mac:
                return port

    def contains(self, port_address):
        for port in self.ports:
            if port.MAC == port_address:
                return True
        return False

    def add_port_to_spanning_tree(self, vlan_id, port):
        self.add_vlan(vlan_id)
        if vlan_id in self.spanning_tree_instances:
            self.spanning_tree_instances[vlan_id].append(port)
        else:
            self.spanning_tree_instances[vlan_id] = list()
            self.spanning_tree_instances[vlan_id].append(port)

    def add_vlan(self, vlan_id):
        if vlan_id not in self.vlans:
            self.vlans.append(vlan_id)

    def there_is_root_port(self, vlan_id):
        for port in self.spanning_tree_instances[vlan_id]:
            if port.status == 'Root':
                return True
        return False

    def all_root_port_found(self):
        for vlan_id in self.vlans:
            found = False
            for port in self.spanning_tree_instances[vlan_id]:
                if port.status == 'Root':
                    found = True

            if not found:
                return False
        return True

    def get_blocked_port(self):
        out = list()
        for port in self.ports:
            if port.status == 'Blocked':
                out.append(port)
        return out

    def get_blocked_port_per_vlan(self, vlan_id):
        out = list()
        for port in self.ports:
            if port.status == 'Blocked':
                out.append(port)
        return out

    def get_vlans(self):
        return self.vlans


class Port:
    def __init__(self, n, m):
        self.name = n
        self.MAC = m
        self.status = "Blocked"

    def set_port_as_designated(self):
        self.status = "Designated"

    def set_port_as_root(self):
        self.status = "Root"

    def set_port_as_blocked(self):
        self.status = "Blocked"
