import scapy.all as scapy
import os
import subprocess
import argparse
from scapy.layers.l2 import Ether, Dot1Q
from termcolor import colored

def check_root():
    if os.geteuid() != 0:
        print(colored("[-] This script must be run as root!", "light_red"))
        exit(1)

def get_interfaces():
    interfaces = os.listdir('/sys/class/net/')
    return [iface for iface in interfaces if iface != 'lo']

def get_ip_address(interface):
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                return line.split()[1].split('/')[0]
    except:
        return "Unknown"

def sniff_vlans(interface):
    print(f"[+] Listening on {interface} for VLAN tagged packets...")
    def process_packet(packet):
        if packet.haslayer(Dot1Q):
            vlan_id = packet[Dot1Q].vlan
            src_mac = packet[Ether].src
            print(f"[✓] Found VLAN: {vlan_id} (Source MAC: {src_mac})")
    
    scapy.sniff(iface=interface, prn=process_packet, store=False)

def main():
    print(colored("\n========== VLAN Scanner by Swack3r ==========", "cyan"))
    check_root()
    
    parser = argparse.ArgumentParser(description="VLAN Scanner for Kali Linux")
    parser.add_argument("-i", "--interface", help="Specify the network interface to use", required=False)
    args = parser.parse_args()
    
    interfaces = get_interfaces()
    
    if not interfaces:
        print("[-] No active network interfaces found.")
        return
    
    if args.interface:
        interface = args.interface
        if interface not in interfaces:
            print(f"[-] Specified interface {interface} not found. Available: {', '.join(interfaces)}")
            return
    else:
        print(f"[+] Available interfaces: {', '.join(interfaces)}")
        interface = input("[?] Choose an interface: ")
        if interface not in interfaces:
            print("[-] Invalid interface selection.")
            return
    
    print(f"[+] Using interface: {interface}")
    print(f"[+] IP Address: {get_ip_address(interface)}")
    print("[+] Scanning for VLANs... (Press CTRL+C to stop)")
    
    try:
        sniff_vlans(interface)
    except KeyboardInterrupt:
        print("\n[+] Scan stopped by user.")

if __name__ == "__main__":
    main()
