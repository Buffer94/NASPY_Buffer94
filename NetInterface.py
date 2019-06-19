import getpass
import pyshark
from scapy.all import *
from SSHConnettors import *

class NetInterface:

    def __init__(self, interface):
        self.interface = interface
        self.filter = "arp"
        self.timeout = 60
        self.switch_ip = ''
        self.switch_interface = ''
        self.switch_MAC = ''
        self.capture = ''
        self.ssh = 'null'

    def wait_cdp_packet(self):
        print("Wait for CDP Packet ... ")
        cdp_sniff = pyshark.LiveCapture(interface=self.interface, display_filter="cdp")
        cdp_sniff.sniff(packet_count=1)
        pkt = cdp_sniff[0]

        if pkt.cdp.number_of_addresses == '1':
            self.switch_ip = pkt.cdp.nrgyz_ip_address
        self.switch_MAC = pkt.eth.src
        self.switch_interface = pkt.cdp.portid

    def ssh_connection(self):
        switch_ip = input('switch_ip: ')
        switch_name = input('switch username: ')
        switch_pwd = getpass.getpass('password: ')
        switch_en_pwd = getpass.getpass('enable password: ')

        print("Connecting to SSH...")
        #TODO SWITCH FOR VENDOR ADDRESS
        self.ssh = CiscoSSH(switch_ip, switch_name, switch_pwd, switch_en_pwd, self.switch_interface, self.timeout)
        # monitor.add_switch(ssh.take_interfaces())

    def enable_monitor_mode(self):
        if self.ssh != 'null':
            self.ssh.enable_monitor_mode()

    def take_interfaces(self):
        if self.ssh != 'null':
            self.ssh.take_interfaces()

    def send_dhcp_discover(self):
        print('sending dhcp discover...')
        local_mac = get_if_hwaddr(self.interface)
        local_mac_raw = get_if_raw_hwaddr(self.interface)
        broad_mac = 'ff:ff:ff:ff:ff:ff'
        source_ip = '0.0.0.0'
        dest_ip = '255.255.255.255'

        DHCP_discover = Ether(src=local_mac, dst=broad_mac) / IP(src=source_ip, dst=dest_ip) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=local_mac_raw, xid=RandInt()) / DHCP(
            options=[('message-type', 'discover'), 'end'])
        sendp(DHCP_discover, iface=self.interface)

    def send_dns_request(self):
        print('sending dns request...')
        #TODO

    def sniff(self):
        print('start sniffing...')
        self.capture = pyshark.LiveCapture(interface=self.interface)
        self.capture.sniff(timeout=self.timeout)