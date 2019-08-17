import getpass
import pyshark
from scapy.all import *
from SSHConnettors import *
import base64
import os
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class NetInterface:

    def __init__(self, interface, password=None):
        self.interface = interface
        self.timeout = 30
        self.switch_ip = None
        self.switch_interface = None
        self.switch_MAC = None
        self.capture = None
        self.ssh = None
        self.password = password
        self.kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'2048',
                iterations=100000,
                backend=default_backend()
            )

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
        if self.switch_ip is None:
            self.switch_ip = input('switch_ip: ')
        switch_name = input('switch username: ')
        switch_pwd = getpass.getpass('password: ')
        switch_en_pwd = getpass.getpass('enable password: ')

        print("Connecting to SSH...")
        #TODO SWITCH FOR VENDOR ADDRESS
        self.ssh = CiscoSSH(self.switch_interface, self.timeout)
        self.ssh.connect_with_attempts(self.switch_ip, switch_name, switch_pwd, switch_en_pwd, 20)

    def parameterized_ssh_connection(self, switch_ip, switch_name, switch_pwd, switch_en_pwd, switch_interface,
                                     attempts=0):
        print("Connecting to SSH...")
        #TODO SWITCH FOR VENDOR ADDRESS
        self.ssh = CiscoSSH(switch_interface, self.timeout)

        if attempts == 0:
            self.ssh.connect(switch_ip, switch_name, switch_pwd, switch_en_pwd)
        else:
            self.ssh.connect_with_attempts(switch_ip, switch_name, switch_pwd, switch_en_pwd, attempts)

    def ssh_no_credential_connection(self):
        if self.switch_ip is not None:
            print("Connecting to SSH...")

            # TODO SWITCH FOR VENDOR ADDRESS
            self.ssh = CiscoSSH(self.switch_interface, self.timeout)

            credentials = self.read_credentials()
            index = 0
            (name, pwd, en_pwd) = credentials[index]
            connected = self.ssh.connect_with_attempts(self.switch_ip, name, pwd, en_pwd, 5)

            while index < (len(credentials)-1) and not connected:
                index += 1
                (name, pwd, en_pwd) = credentials[index]
                connected = self.ssh.connect_with_attempts(self.switch_ip, name, pwd, en_pwd, 5)

            return connected

    def enable_monitor_mode(self):
        if self.ssh is not None:
            self.ssh.enable_monitor_mode()

    def take_interfaces(self):
        if self.ssh is not None:
            return self.ssh.take_interfaces()

    def send_dhcp_discover(self):
        print('sending DHCP discover...')
        local_mac = get_if_hwaddr(self.interface)
        fam, local_mac_raw = get_if_raw_hwaddr(self.interface)
        broad_mac = 'ff:ff:ff:ff:ff:ff'
        source_ip = '0.0.0.0'
        dest_ip = '255.255.255.255'

        DHCP_discover = Ether(src=local_mac, dst=broad_mac) / IP(src=source_ip, dst=dest_ip) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=local_mac_raw) / DHCP(
            options=[('message-type', 'discover'), 'end'])
        sendp(DHCP_discover, iface=self.interface, count=15, inter=0.5, verbose=False)

    def send_arp_request(self, ip, netmask):
        print('sending ARP Request...')
        broad_mac = 'ff:ff:ff:ff:ff:ff'
        subnet_ip = '%s/%s' % (ip, netmask)
        arp_request = Ether(dst=broad_mac)/ARP(pdst=subnet_ip)

        sendp(arp_request, verbose=False, iface=self.interface, inter=0.5)

    def send_dns_request(self):
        print('sending DNS Request...')
        # for i in range(15):
        #     print("sending %s 's dns request..." % i)
        #TODO

    def read_credentials(self):
        credentials = list()

        if self.password is not None:
            password = self.password.encode()

            key = base64.urlsafe_b64encode(self.kdf.derive(password))
            fernet = Fernet(key)

            raw_data = open('credentials.naspy')
            data = json.load(raw_data)

            for name in data:
                raw_item = data[name]
                pwd = fernet.decrypt(raw_item[0].encode()).decode()
                en_pwd = fernet.decrypt(raw_item[1].encode()).decode()
                credentials.append((name, pwd, en_pwd))

            return credentials
