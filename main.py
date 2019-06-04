from RogueDhcpMonitor import *
from Sniffer import *
import sys

usage = "Usage: -i [interface], -m [mode]"

print ("Welcome to NasPy --Buffer94_Module--")
# print (usage)

if len(sys.argv) < 5:
    print("Error, you must enter an Interface name and a modality")
    print (usage)
    sys.exit(0)

else:
    if sys.argv[1] == '-i':
        interface = sys.argv[2]
    else:
        print (usage)
        sys.exit(0)

    if sys.argv[3] == '-m':
        if sys.argv[4] == 'arp':
            type = 'arp'
        if sys.argv[4] == 'dhcp':
            type = 'dhcp'
        if sys.argv[4] == 'vlan':
            type = 'vlan'
    else:
        sys.exit(0)


# sender = RogueDHCPMonitor(interface)
sniffer = Sniffer(interface, type)

sniffer.start()
# sender.send_discover()
