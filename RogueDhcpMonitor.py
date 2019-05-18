#! /usr/bin/env python

from threading import Thread

import pyshark
from scapy.all import *


#Rogue DHCP Monitor module

#How it works:
# 1 - Send a DHCP Discover Package (Using Scapy or DHClient package)
# 2 - Start sniffing package
# 3 - Wait for a DHCP Offer (if i receive 2 different DHCP offer means that i have a Rogue DHCP server on my network)
# 4 - Print output that contains source IP and ARP of DHCP Servers.

class RogueDHCPMonitor():

    def __init__(self):
        self.interface = 'ens3'
        self.myhostname = 'raspberrypi'
        self.localmac = get_if_hwaddr(self.interface)
        self.useless, self.localmacraw = get_if_raw_hwaddr(self.interface)
        self.broadMAC = 'ff:ff:ff:ff:ff:ff'
        self.sourceIP = '0.0.0.0'
        self.destIP = '255.255.255.255'

    def sendDiscover(self):
        DHCP_discover = Ether(src=self.localmac, dst=self.broadMAC) / IP(src=self.sourceIP, dst=self.destIP) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=self.localmacraw, xid=RandInt()) / DHCP(
            options=[('message-type', 'discover'), 'end'])
        sendp(DHCP_discover, iface=self.interface)


class Sniffer(Thread):

    def __init__(self):
        Thread.__init__(self)
        self.DHCPOffers = []
        self.interface = 'ens3'

    def run(self):
        capture = pyshark.LiveCapture(interface=self.interface, display_filter='bootp')

        print("Starting Sniffing...")

        for packet in capture.sniff_continuously():
            if (packet.bootp.option_dhcp == '2'):
                if len(self.DHCPOffers) > 0:
                    found = False
                    for DHCPOffer in self.DHCPOffers:
                        if DHCPOffer.bootp.option_dhcp_server_id == packet.bootp.option_dhcp_server_id:
                            found = True
                    if found == False:
                        print("I've found this DHCP Server:")
                        print("Server IP: %s" % (packet.bootp.option_dhcp_server_id ))
                        print("Server MAC: %s" % (packet.eth.src))
                        self.DHCPOffers.append(packet)
                else:
                    print("I've found this DHCP Server:")
                    print("Server IP: %s" % (packet.bootp.option_dhcp_server_id))
                    print("Server MAC: %s" % (packet.eth.src))
                    self.DHCPOffers.append(packet)