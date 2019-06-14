
class STPMonitor:

    def __init__(self):
        self.switches_table = list()

    def update_switches_table(self):
        print('MIAO')
    #     sender_mac = packet.eth.src
    #     bridge_id = packet.stp.bridge_hw
    #     bridge_port = packet.stp.port
    #
    #     if bridge_id in self.switches_table:
    #         if sender_mac not in self.switches_table[bridge_id]:
    #             self.switches_table[bridge_id].append((sender_mac, ""))
    #     else:
    #         self.switches_table[bridge_id] = list()
    #         self.switches_table[bridge_id].append(sender_mac)
    #
    #     self.print_switches_table
    #
    # def print_switches_table(self):
    #     for bridge_id in self.switches_table:
    #         print("Bridge: %s" % bridge_id)
    #         for port in self.switches_table[bridge_id]:
    #             print("port_mac: %s" % port)


class Switch:

    def __init__(self):
        self.bridge_id
        self.bridge_priority
        self.is_root_bridge
        self.ports = list()

    def add_ports(self, port_address):
        for curr_port in self.ports:
            if not port_address == curr_port[0]:
                self.ports.append((port_address, "Blocked"))

    def set_designated_port(self, port_address):
        for port in self.ports:
            if port[0] == port_address:
                port[1] = "Designated"

    def set_root_port(self, port_address):
        for port in self.ports:
            if port[0] == port_address:
                port[1] = "Root"

    def print_port_status(self):
        for port in self.ports:
            print("Port: %s, Status: %s" % (port[0], port[1]))

