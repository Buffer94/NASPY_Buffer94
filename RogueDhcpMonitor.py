#! /usr/bin/env python
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
        self.interface = 'wlp3s0'
        self.myhostname = 'raspberrypi'
        self.localmac = get_if_hwaddr(self.interface)
        self.broadMAC = 'ff:ff:ff:ff:ff:ff'
        self.sourceIP = '0.0.0.0'
        self.destIP = '255.255.255.255'
        self.DHCPOffers = []


    def sendDiscover(self):
        # 1 - Send a DHCP Discover Package
        DHCP_discover = Ether(src=self.localmac, dst=self.broadMAC) / IP(src=self.sourceIP, dst=self.destIP) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=self.localmac, xid=RandInt()) / DHCP(
            options=[('message-type', 'discover'), 'end'])
        sendp(DHCP_discover, iface=self.interface)

    def startSniffing(self):
        # 2 - Start sniffing package
        capture = pyshark.LiveCapture(interface=self.interface, display_filter='bootp', only_summaries=True)
        capture.sniff(timeout=50)

        for packet in capture:
            if(packet.bootp.option_dhcp == '1'):
                print("DHCP Discover")
            if (packet.bootp.option_dhcp == '2'):
                self.DHCPOffers.append(packet)
                # print("DHCP Offer \n Server IP: %s\n Server MAC: "% (packet.eth.src))
            if (packet.bootp.option_dhcp == '3'):
                print("DHCP Request")
            if (packet.bootp.option_dhcp == '5'):
                print("DHCP ACK")

        if len(self.DHCPOffers) > 1:
            print("I've found this DHCP Server:")
            for DHCPOffer in self.DHCPOffers:
                print("Server IP: %s\n Server MAC: %s"% (DHCPOffer.ip.addr, DHCPOffer.eth.src))