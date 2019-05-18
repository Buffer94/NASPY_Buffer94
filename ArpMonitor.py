
class ArpMonitor:

    def __init__(self):
        self.arp_table = dict()

    def find_duplicate(self, packet):
        sender_mac = packet.arp.src_hw_mac
        sender_ip = packet.arp.src_proto_ipv4

        if sender_mac in self.arp_table:
            if not (sender_ip in self.arp_table[sender_mac]):
                self.arp_table[sender_mac].append(sender_ip)

            if len(self.arp_table[sender_mac]) > 1:
                print("Conflict Found, duplicate IPs %s for Mac address: %s" % (self.arp_table[sender_mac], sender_mac))

        else:
            self.arp_table[sender_mac] = list()
            self.arp_table[sender_mac].append(sender_ip)
            # for mac in self.arp_table:
                # print("mac %s :-> ip %s" % (mac, self.arp_table[mac]))
            # print ("END ARP TABLE")