class Switch:

    def __init__(self, n):
        self.name = n
        self.bridge_id = 0
        self.bridge_priority = 0
        self.is_root_bridge = True
        self.ports = list()

    def set_bridge_info(self, b_id, b_p, rb):
        self.bridge_id = b_id
        self.bridge_priority = b_p
        self.is_root_bridge = rb

    def add_ports(self, port):
        for curr_port in self.ports:
            if not port.MAC == curr_port[0].MAC:
                self.ports.append((port, "Blocked"))

    def set_designated_port(self, port_address):
        for port in self.ports:
            if port[0].MAC == port_address:
                port[1] = "Designated"

    def set_root_port(self, port_address):
        for port in self.ports:
            if port[0].MAC == port_address:
                port[1] = "Root"

    def print_port_status(self):
        for port in self.ports:
            print("Port: %s - Address: %s, Status: %s" % (port[0].name, port[0].MAC, port[1]))


class Port:

    def __init__(self, n, m):
        self.name = n
        self.MAC = m
