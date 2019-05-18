from threading import Thread
from RogueDhcpMonitor import *
from ArpMonitor import *
import pyshark


class Sniffer(Thread):

    def __init__(self, interface, mode):
        Thread.__init__(self)
        self.interface = interface
        self.filter = "arp"
        self.mode = mode

    def run(self):
        if self.mode == 'arp':
            self.filter = 'arp'
            monitor = ArpMonitor()
        if self.mode == 'dhcp':
            self.filter = 'bootp'
            monitor = RogueDHCPMonitor(self.interface)

        capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.filter)

        print("Starting Sniffing...")

        for packet in capture.sniff_continuously():
            if self.mode == 'dhcp':
                monitor.monitor_DHCP(packet)

            if self.mode == 'arp':
                monitor.find_duplicate(packet)
