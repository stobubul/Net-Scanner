#!/usr/bin/env python3
#!/usr/bin/env python

import scapy.all as scapy
import optparse


def intro():
    print(r'''
   \  |        |         ___|                                         
    \ |   _ \  __|     \___ \    __|   _` |  __ \   __ \    _ \   __| 
  |\  |   __/  |             |  (     (   |  |   |  |   |   __/  |    
 _| \_| \___| \__|     _____/  \___| \__,_| _|  _| _|  _| \___| _|    
                                             
   _|             | _)                                            
   _| _ \   _|    |  |    \   |  | \ \ /                          
 _| \___/ _|     _| _| _| _| \_,_|  _\_\                          
''')
    print(r'''
                                         _____ __  
                     _  _  _| _  |_     (_  | |__) 
                    |||(_|(_|(-  |_)\/  __) | |__) 
                                    /              
    ''')

def get_arguments():
    parse_object = optparse.OptionParser(usage="%prog [options]")

    parse_object.add_option("-i", "--ip-address",dest="ip",help="IP address to scan    ")
    parse_object.add_option("-t", "--timeout",dest="timeout", type="int", default=1, help="DEFAULT=1, Specific time (sec) to wait for responses    ")

    (inputs, arguments) = parse_object.parse_args()

    if inputs.ip is None:
        print("[-] IP address is required, use --help for more info.    ")
    return inputs

def arp_request(ip_address):
     return scapy.ARP(pdst=ip_address)

def broadcast(arp_request_packet, timeout=1):
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet # Merges broadcast and arp request package
    (answered_list, unanswered_list) = scapy.srp(combined_packet,timeout=int(timeout))

    if answered_list:
        print("..........................................\nIP Address\t\tMAC Address\n..........................................")
        for sent, answer in answered_list:
            print(answer.psrc + "\t\t" + answer.hwsrc)
    else:
        print("\n[-] No responses received. You may want to check your internet connection or ip address you have entered.")

def main():
    intro()
    options = get_arguments()
    if options.ip:
        arp_req_package = arp_request(options.ip)
        broadcast(arp_req_package,options.timeout)
main()




