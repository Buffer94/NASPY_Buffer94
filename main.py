from RogueDhcpMonitor import *

monitor = RogueDHCPMonitor()

monitor.sendDiscover()
monitor.startSniffing()