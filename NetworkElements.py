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
        self.bridge_id = ''
        self.bridge_priority = 0
        self.is_root_bridge = True
        self.ports = list()
        self.ip = ip
        self.password = pwd
        self.en_password = en_pwd
        self.connected_interface = conn_interface

    def set_bridge_info(self, b_id, b_p, rb):
        self.bridge_id = b_id
        self.bridge_priority = b_p
        self.is_root_bridge = rb

    def add_ports(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def set_designated_port(self, port_address):
        for port in self.ports:
            if port.MAC == port_address:
                port.set_port_as_designated()

    def set_root_port(self, port_address):
        for port in self.ports:
            if port.MAC == port_address:
                port.set_port_as_root()

    def print_port_status(self):
        for port in self.ports:
            print("Port: %s - Address: %s, Status: %s" % (port.name, port.MAC, port.status))

    def contains(self, port_address):
        for port in self.ports:
            if port.MAC == port_address:
                return True
        return False

    def get_blocked_port(self):
        out = list()
        there_is_root = False
        for port in self.ports:
            if not there_is_root:
                if port.status == 'Root':
                    there_is_root = True
                if port.status == 'Blocked':
                    out.append(port)
        if there_is_root:
            out = list()
        return out


class Port:

    def __init__(self, n, m):
        self.name = n
        self.MAC = m
        self.status = "Blocked"
        self.pkg_counter = 0

    def increase_pkg_counter(self):
        if self.status == "Blocked":
            self.pkg_counter += 1

    def set_port_as_designated(self):
        self.status = "Designated"
        self.pkg_counter = 0

    def set_port_as_root(self):
        self.status = "Root"

    def set_port_as_blocked(self):
        self.status = "Blocked"
