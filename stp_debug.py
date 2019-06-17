from Sniffer import *
import sys

usage = "Usage: -i [interface], -m [mode]"

print ("Welcome to NasPy --Buffer94_Module-- ####STP_DEBUG####")
# print (usage)

interface = 'enp0s3'
type = 'stp'

sniffer = Sniffer(interface, type)

sniffer.start()
