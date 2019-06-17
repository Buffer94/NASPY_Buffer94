
class STPMonitor:

    def __init__(self):
        self.switches_table = list()

    def update_switches_table(self, packet):
        print("Updating Switches Table!")
        print("Packet Address: %s " % packet.eth.src)
        sender_mac = packet.eth.src
        for switch in self.switches_table:
            print("bridge_id : %s , pkt_bridge_id: %s" % (switch.bridge_id, packet.stp.bridge_hw))
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
