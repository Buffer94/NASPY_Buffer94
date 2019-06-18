from Sniffer import *
from NetInterface import *
import sys

usage = "Usage: -i [interface], [-m [mode]], [-h [help]]"
full_usage = "mode options: \n" \
             "arp: IDS system for ARP protocol." \
             "dhcp: IDS system for Rogue DHCP Attack" \
             "dns: IDS system for DNS Hijack Attack" \
             "vlan: Monitoring vlan that pass through a switch" \
             "stp: Monitoring STP Status and eventually failure" \
             "default: When no other options are chosen on default this switch will perform all modality"

print ("Welcome to NasPy --Buffer94_Module--")

if len(sys.argv) < 5:
    print("Error, you must enter an Interface name and a modality")
    print(usage)
    sys.exit(0)

else:
    if sys.argv[1] == '-i':
        interface = sys.argv[2]
    else:
        if sys.argv[1] == '-h':
            print('%s \n %s' % (usage, full_usage))
        else:
            print (usage)
        sys.exit(0)

    mode = 'no'
    if sys.argv[3] == '-m':
        if sys.argv[4] == 'arp':
            mode = 'arp'
        if sys.argv[4] == 'dhcp':
            mode = 'dhcp'
        if sys.argv[4] == 'vlan':
            mode = 'vlan'
        if sys.argv[4] == 'stp':
            mode = 'stp'
        if sys.argv[4] == 'dns':
            mode = 'dns'
    else:
        mode = 'all'

if mode == 'no':
    print('%s \n %s' % (usage, full_usage))
    sys.exit(0)

netinterface = NetInterface(interface)




#
# sniffer = Sniffer(interface, type)
#
# sniffer.start()
