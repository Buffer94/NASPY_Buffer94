from builtins import print


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


class SpanningTreeInstance:

    def __init__(self, vlan_id):
        self.ports = list()
        self.vlan_id = vlan_id
        self.priority = 60000
        self.bridge_id = None
        self.root_bridge_id = None
        self.root_bridge = False

    def get_blocked_port(self):
        out = list()
        for port in self.ports:
            if port.pvlan_status[self.vlan_id] == "Blocked":
                out.append(port)
        return out

    def add_port(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def remove_port(self, port):
        if port in self.ports:
            self.ports.remove(port)

    def update_stp_info(self, priority, bridge_id, root_bridge_id):
        self.priority = int(priority) + int(self.vlan_id)
        self.bridge_id = bridge_id
        self.root_bridge_id = root_bridge_id
        self.check_root_bridge()

    def check_root_bridge(self):
        self.root_bridge = True if self.bridge_id == self.root_bridge_id else False

    def there_is_root_port(self):
        for port in self.ports:
            if port.pvlan_status[self.vlan_id] == "Root":
                return True
        return False

    def print_stp_status(self):
        print("Spanning Tree on Vlan: %s" % self.vlan_id)
        print("Root Bridge: %s - Bridge: %s - Priority: %s" % (self.root_bridge_id, self.bridge_id, self.priority))
        if self.root_bridge:
            print("This switch is the Root Bridge")
        for port in self.ports:
            print("Port: %s - Address: %s, Status: %s" % (port.name, port.MAC, port.pvlan_status[self.vlan_id]))


class Switch:

    def __init__(self, n, ip, pwd, en_pwd, conn_interface):
        self.name = n
        self.bridge_id = None
        self.ports = list()
        self.ip = ip
        self.password = pwd
        self.en_password = en_pwd
        self.connected_interface = conn_interface
        self.spanning_tree_instances = dict()

    def get_interfaces(self):
        interfaces = list()
        for port in self.ports:
            interfaces.append(port.name)
        return interfaces

    def set_stp_priority(self, vlan, priority):
        self.spanning_tree_instances[vlan].priority = int(priority) + int(vlan)

    def set_stp_root_id(self, vlan, root_id):
        self.spanning_tree_instances[vlan].root_bridge_id = root_id
        self.spanning_tree_instances[vlan].check_root_bridge()

    def add_ports(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def set_designated_port(self, port_address, vlan_id, override=False, priority=None, b_id=None):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_designated(vlan_id, override)

    def set_blocked_port(self, port_address, vlan_id, override=False, priority=None, b_id=None):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_blocked(vlan_id, override)

    def set_root_port(self, port_address, vlan_id, override=False, priority=None, b_id=None):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_root(vlan_id, override)

    def print_spanning_tree(self):
        for vlan_id in self.spanning_tree_instances:
            self.spanning_tree_instances[vlan_id].ports.sort(key=self.take_MAC)
            self.spanning_tree_instances[vlan_id].print_stp_status()

    @staticmethod
    def take_MAC(port):
        return port.MAC

    def get_port(self, port_mac):
        for port in self.ports:
            if port.MAC == port_mac:
                return port

    def get_port_by_name(self, port_name):
        for port in self.ports:
            if port.name == port_name:
                return port

    def contains(self, port_address):
        for port in self.ports:
            if port.MAC == port_address:
                return True
        return False

    def add_port_to_spanning_tree(self, vlan_id, port, priority=None, r_id=None):
        if vlan_id in self.spanning_tree_instances:
            self.spanning_tree_instances[vlan_id].add_port(port)
        else:
            self.spanning_tree_instances[vlan_id] = SpanningTreeInstance(vlan_id)
            self.spanning_tree_instances[vlan_id].add_port(port)
        if r_id is not None and priority is not None:
            self.spanning_tree_instances[vlan_id].update_stp_info(priority, self.bridge_id, r_id)

    def remove_port_from_stp(self, vlan_id, port):
        self.spanning_tree_instances[vlan_id].remove_port(port)

    def there_is_root_port(self, vlan_id):
        return self.spanning_tree_instances[vlan_id].there_is_root_port()

    def all_root_port_found(self):
        for vlan_id in self.get_vlans():
            if not self.spanning_tree_instances[vlan_id].root_bridge:
                found = self.spanning_tree_instances[vlan_id].there_is_root_port()

                if not found:
                    return False
        return True

    def get_trunk_port(self):
        out = list()
        for port in self.ports:
            if port.trunk:
                out.append(port)
        return out

    def get_blocked_port(self):
        out = list()
        for port in self.ports:
            if len(port.pvlan_status) == 0 or port.trunk:
                out.append(port)
        return out

    def get_blocked_port_per_vlan(self, vlan_id):
        out = list()
        for port in self.ports:
            if port.pvlan_status[vlan_id] == 'Blocked':
                out.append(port)
        return out

    def get_vlans(self):
        return self.spanning_tree_instances.keys()


class Port:
    def __init__(self, n, m):
        self.name = n
        self.MAC = m
        self.pvlan_status = dict()
        self.trunk = False

    def set_port_as_designated(self, vlan_id=1, override=False):
        if len(self.pvlan_status) > 0 and vlan_id not in self.pvlan_status and not self.trunk:
            self.trunk = True
        if override or vlan_id not in self.pvlan_status:
            self.pvlan_status[vlan_id] = "Designated"

    def set_port_as_root(self, vlan_id=1, override=False):
        if len(self.pvlan_status) > 0 and vlan_id not in self.pvlan_status and not self.trunk:
            self.trunk = True
        if override or vlan_id not in self.pvlan_status:
            self.pvlan_status[vlan_id] = "Root"

    def set_port_as_blocked(self, vlan_id=1, override=False):
        if len(self.pvlan_status) > 0 and vlan_id not in self.pvlan_status and not self.trunk:
            self.trunk = True
        if override or vlan_id not in self.pvlan_status:
            self.pvlan_status[vlan_id] = "Blocked"

    def get_vlan(self):
        return self.pvlan_status.keys()

    def contain_vlan(self, vlan_id):
        if vlan_id in self.pvlan_status:
            return True
        return False

    def remove_vlan(self, vlan_id):
        if vlan_id in self.pvlan_status:
            del self.pvlan_status[vlan_id]
            if len(self.pvlan_status) < 2:
                self.trunk = False
                print("Port %s is no longer TRUNK!" % self.name)
