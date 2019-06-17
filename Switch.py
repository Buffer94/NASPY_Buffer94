class Switch:

    def __init__(self, n):
        self.name = n
        self.bridge_id = ''
        self.bridge_priority = 0
        self.is_root_bridge = True
        self.ports = list()

    def set_bridge_info(self, b_id, b_p, rb):
        self.bridge_id = b_id
        self.bridge_priority = b_p
        self.is_root_bridge = rb

    def add_ports(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def set_designated_port(self, port_address):
        print("port address: %s" % port_address)
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
