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
        self.interface = 'eth0'
        self.myhostname = 'raspberrypi'
        self.localmac = get_if_hwaddr(self.interface)
        self.useless, self.localmacraw = get_if_raw_hwaddr(self.interface)
        self.broadMAC = 'ff:ff:ff:ff:ff:ff'
        self.sourceIP = '0.0.0.0'
        self.destIP = '255.255.255.255'

    def sendDiscover(self):
        # 1 - Send a DHCP Discover Package
        DHCP_discover = Ether(src=self.localmac, dst=self.broadMAC) / IP(src=self.sourceIP, dst=self.destIP) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=self.localmacraw, xid=RandInt()) / DHCP(
            options=[('message-type', 'discover'), 'end'])
        sendp(DHCP_discover, iface=self.interface)


class Sniffer(Thread):

    def __init__(self):
        Thread.__init__(self)
        self.DHCPOffers = []
        self.interface = 'eth0'

    def run(self):
        # 2 - Start sniffing package
        capture = pyshark.LiveCapture(interface=self.interface, display_filter='bootp')

        while (True):
            for packet in capture.sniff_continuously(packet_count=1):
                # if (packet.bootp.option_dhcp == '1'):
                #     print("DHCP Discover")
                # print(packet.bootp)
                if (packet.bootp.option_dhcp == '2'):
                    self.DHCPOffers.append(packet)
                    # print("I've found this DHCP Server:")
                    # print("Server IP: %s\n Server MAC: %s" % (packet.ip.addr, packet.eth.src))
                    for DHCPOffer in self.DHCPOffers:
                        if(DHCPOffer.eth.src != packet.eth.src):
                           self.DHCPOffers.append(packet)
                # if (packet.bootp.option_dhcp == '3'):
                #     print("DHCP Request")
                # if (packet.bootp.option_dhcp == '5'):
                #     print("DHCP ACK")

            # 3 - Wait for a DHCP Offer (if i receive 2 different DHCP offer means that i have a Rogue DHCP server on my network)
            # 4 - Print output that contains source IP and ARP of DHCP Servers.
            if len(self.DHCPOffers) > 1:
                print("I've found this DHCP Server:")
                for DHCPOffer in self.DHCPOffers:
                    print("Server IP: %s" % (DHCPOffer.ip.addr))
                    print("Server MAC: %s" % (DHCPOffer.eth.src))
            else:
                sender = RogueDHCPMonitor()
                sender.sendDiscover()
