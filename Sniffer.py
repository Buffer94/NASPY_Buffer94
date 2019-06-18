from Monitors.RogueDhcpMonitor import *
from Monitors.ArpMonitor import *
from Monitors.VlanMonitor import *
from Monitors.STPMonitor import *
from SSH_Connettors.CiscoModule import *
import getpass
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
        if self.mode == 'vlan':
            self.filter = 'vlan'
            monitor = VlanMonitor()
        if self.mode == 'stp':
            self.filter = 'stp'

            print("Enabling STP Monitoring...")

            monitor = STPMonitor()

            print("Wait for CDP Packet ... ")
            cdp_sniff = pyshark.LiveCapture(interface=self.interface, display_filter="cdp")
            cdp_sniff.sniff(packet_count = 1)
            pkt = cdp_sniff[0]

            if pkt.cdp.number_of_addresses == '1':
                switch_ip = pkt.cdp.nrgyz_ip_address
            else:
                switch_ip = input('switch_ip: ')

            switch_interface = pkt.cdp.portid
            switch_name = input('switch username: ')
            switch_pwd = getpass.getpass('password: ')
            switch_en_pwd = getpass.getpass('enable password: ')
            timeout = 60

            print("Connecting to SSH...")
            ssh = CiscoModule(switch_ip, switch_name, switch_pwd, switch_en_pwd, switch_interface, timeout)
            monitor.add_switch(ssh.take_interfaces())
            ssh.enable_monitor_mode()

        capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.filter)

        print("Starting Sniffing...")

        for packet in capture.sniff_continuously():
            if self.mode == 'dhcp':
                monitor.monitor_DHCP(packet)

            if self.mode == 'arp':
                monitor.update_arp_table(packet)

            if self.mode == 'vlan':
                monitor.update_vlan_table(packet)

            if self.mode == 'stp':
                monitor.update_switches_table(packet)
