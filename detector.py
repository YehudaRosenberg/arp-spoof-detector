#!/usr/bin/env python
#TODO 1: Rebuild the code with OOP 
#TODO 2: Create windows program with tkinter (maybe use PyScript?)
#TODO 3: Think about adding a feature like sending email to the corrupted netowrk owner (smtlib etc.) 

import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def sniff():
    scapy.sniff(store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            corrupted_iface = scapy.conf.iface
            if real_mac != response_mac:
                attack_msg = f"[+] You are under attack!! \nAttacker's MAC Address is {response_mac}. \nThe Corrupted interface is {corrupted_iface}"
                print(attack_msg)
        except IndexError:
            pass

sniff()
