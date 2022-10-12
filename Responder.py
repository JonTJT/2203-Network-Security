from scapy.all import *

def handle_packet(packet):
   if (packet[ARP].op == 1 and packet.pdst == "192.168.1.254"):
      #print("Someone is asking about " + packet.pdst)
      replyARP = ARP(op=2, hwsrc="00:00:0c:07:ac:01", psrc=packet.pdst, hwdst=packet[Ether].src, pdst=packet.psrc)
      
      reply = Ether(dst=packet[Ether].src, src="00:00:0c:07:ac:01") / replyARP
      
      print(reply.show)
      sendp(reply)
   return

while True:
   sniff(iface = "eth0", count = 1, filter = "arp", prn=handle_packet)