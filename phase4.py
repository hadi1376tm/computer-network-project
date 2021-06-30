from netaddr import IPNetwork, IPAddress, IPRange
import scapy.all as scapy
import time


def check_IP_range(choice):
    IP_list=[]
    if choice == "1":
        start_ip = input("Enter Start IP:")
        while (True):
                try:
                    start_ip = IPAddress(start_ip)
                    break
                except Exception:
                    print("wrong IP format.\n try again.")
                    start_ip = input("Enter Start IP:")
        end_ip = input("Enter End IP:")
        while (True):
            try:
                flag = False
                end_ip = IPAddress(end_ip)
                if (end_ip < start_ip):
                    flag = True
                    raise Exception()
                break
            except Exception:
                if (flag):
                    print("end ip must be after start ip")
                else:
                    print("wrong IP format.\n try again.")
                end_ip = input("Enter End ip:")
        network =IPRange(start_ip, end_ip)
        
    if choice == "2":
        ip = input("Enter IP with mask:")
        while (True):
                try:
                    network=IPNetwork(ip)
                    break
                except Exception:
                    print("wrong IP format.\n try again.")
                    ip = input("Enter IP with mask:")

    for i in network:
        IP_list.append(str(i))
    return IP_list




if __name__ == "__main__":
    print("1- IP with range.")
    print("2- IP with mask (x.x.x.x/x). ")
    input_choice = input("Choose input IP range method(1/2):")
    Network = check_IP_range(input_choice)
    Timeout_input = input("Enter Timeout (s):")
    while True:
        try:
            Timeout = int(Timeout_input)
            break
        except Exception:
            print("Wrong timeout value.")
            Timeout_input = input("Enter Timeout (s):")

    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answers, unans = scapy.srp(ether / scapy.ARP(pdst=Network), timeout=Timeout)
    for i in answers:
        Network[Network.index(i.answer.payload.fields["psrc"])] =Network[Network.index(i.answer.payload.fields["psrc"])]+ ":"+i.answer.payload.fields["hwsrc"]
    for i in range(0,len(Network)):
        if ":" not in Network[i]:
            Network[i]+=": Is Down"
    for i in Network:
        print(i)
