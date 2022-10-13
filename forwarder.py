from scapy.all import *
import time

while(True):
    pkt = sniff(filter="(tcp or ip or udp or icmp) and not src port 1985 and not broadcast")
    toSend = pkt[0]
    toSend[Ether].dst = "00:c8:8b:6d:71:e0"
    toSend.show()
    sendp(toSend, iface="eth0")

