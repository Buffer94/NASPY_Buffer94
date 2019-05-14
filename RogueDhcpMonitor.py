#! /usr/bin/env python
import pyshark
from scapy.all import *

#Rogue DHCP Monitor module

#How it works:
# 1 - Send a DHCP Discover Package (Using Scapy or DHClient package)
# 2 - Start sniffing package
# 3 - Wait for a DHCP Offer (if i receive 2 different DHCP offer means that i have a Rogue DHCP server on my network)
# 4 - Print output that contains source IP and ARP of DHCP Servers.

conf.checkIPaddr=False

# configuration
localiface = 'wlp3s0'
requestMAC = '1c:4d:70:59:b4:dd '
myhostname='raspberrypi'
localmac = get_if_hwaddr(localiface)
localmacraw = requestMAC.replace(':','')


# craft DHCP DISCOVER
dhcp_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options=[('message-type', 'discover'), 'end'])
print (dhcp_discover.display())

# send discover, wait for reply
dhcp_offer = srp1(dhcp_discover,iface=localiface)
print (dhcp_offer.display())

# craft DHCP REQUEST from DHCP OFFER
myip=dhcp_offer[BOOTP].yiaddr
sip=dhcp_offer[BOOTP].siaddr
xid=dhcp_offer[BOOTP].xid
dhcp_request = Ether(src=localmac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=localmacraw,xid=xid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
print (dhcp_request.display())

# send request, wait for ack
dhcp_ack = srp1(dhcp_request,iface=localiface)
print (dhcp_ack.display())