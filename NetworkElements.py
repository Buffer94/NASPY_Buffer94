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
        self.vlans = list()
        self.stp_info = dict()

    def get_interfaces(self):
        interfaces = list()
        for port in self.ports:
            interfaces.append(port.name)
        return interfaces

    def add_ports(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def set_designated_port(self, port_address, vlan_id, override=False, priority=None, b_id=None):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_designated(vlan_id, override)

    def set_blocked_port(self, port_address, vlan_id, override=False):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port)
                port.set_port_as_blocked(vlan_id, override)

    def set_root_port(self, port_address, vlan_id, override=False):
        print("ASDASDADS - root_port %s - vlan %s" % (port_address, vlan_id))
        for port in self.ports:
            if port.MAC == port_address:
                print("I want to set %s as root for vlan %s" %(port.MAC, vlan_id))
                self.add_port_to_spanning_tree(vlan_id, port)
                port.set_port_as_root(vlan_id, override)

    def print_spanning_tree(self):
        for vlan_id in self.spanning_tree_instances:
            print("Spanning Tree on Vlan: %s" % vlan_id)
            for port in self.spanning_tree_instances[vlan_id]:
                print("Port: %s - Address: %s, Status: %s" % (port.name, port.MAC, port.pvlan_status[vlan_id]))

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

    def add_port_to_spanning_tree(self, vlan_id, port, priority=None, b_id=None):
        self.add_vlan(vlan_id)
        if vlan_id in self.spanning_tree_instances:
            if port not in self.spanning_tree_instances[vlan_id]:
                self.spanning_tree_instances[vlan_id].append(port)
        else:
            self.spanning_tree_instances[vlan_id] = list()
            self.spanning_tree_instances[vlan_id].append(port)
            if b_id is not None and priority is not None:
                if b_id == self.bridge_id:
                    rb = True
                else:
                    rb = False
                self.stp_info[vlan_id] = (priority, rb)

    def add_vlan(self, vlan_id):
        if vlan_id not in self.vlans:
            self.vlans.append(vlan_id)

    def there_is_root_port(self, vlan_id):
        for port in self.spanning_tree_instances[vlan_id]:
            if port.pvlan_status[vlan_id] == "Root":
                return True
        return False

    def all_root_port_found(self):
        for vlan_id in self.vlans:
            found = False
            for port in self.spanning_tree_instances[vlan_id]:
                if port.pvlan_status[vlan_id] == "Root":
                    found = True

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
        return self.vlans


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