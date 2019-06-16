
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

