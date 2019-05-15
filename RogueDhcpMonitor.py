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


    def sendDiscover(self):
        # 1 - Send a DHCP Discover Package
        DHCP_discover = Ether(src=self.localmac, dst=self.broadMAC) / IP(src=self.sourceIP, dst=self.destIP) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=self.localmac, xid=RandInt()) / DHCP(
            options=[('message-type', 'discover'), 'end'])
        sendp(DHCP_discover, iface=self.interface)

    def startSniffing(self):
        # 2 - Start sniffing package
        capture = pyshark.LiveCapture(interface=self.interface, display_filter='bootp', only_summaries=True)
        capture.sniff(timeout=10)

        for packet in capture:
            if(packet.bootp.option_dhcp == '1'):
                print("DHCP Discover")
            if (packet.bootp.option_dhcp == '2'):
                print("DHCP Offer")
            if (packet.bootp.option_dhcp == '3'):
                print("DHCP Request")
            if (packet.bootp.option_dhcp == '5'):
                print("DHCP ACK")



# conf.checkIPaddr=False
#
# # Setup
# interface = 'wlp3s0'
# myhostname='raspberrypi'
# localmac = get_if_hwaddr(interface)
# broadMAC = 'ff:ff:ff:ff:ff:ff'


# 1 - Send a DHCP Discover Package
# DHCP_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=localmac,xid=RandInt())/DHCP(options=[('message-type', 'discover'), 'end'])
# sendp(DHCP_discover, iface=interface)

# 2 - Start sniffing package

# send discover, wait for reply
# dhcp_offer = srp1(dhcp_discover,iface=interface)
# print (dhcp_offer.display())

# craft DHCP REQUEST from DHCP OFFER
# myip=dhcp_offer[BOOTP].yiaddr
# sip=dhcp_offer[BOOTP].siaddr
# xid=dhcp_offer[BOOTP].xid
# dhcp_request = Ether(src=localmac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=localmacraw,xid=xid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
# print (dhcp_request.display())
#
# # send request, wait for ack
# dhcp_ack = srp1(dhcp_request,iface=localiface)
# print (dhcp_ack.display())