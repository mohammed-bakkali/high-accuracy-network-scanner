#!/usr/bin/env python3

import scapy.all as scapy
import argparse
from colorama import Fore, Style, init
import time
import nmap
import getpass
from datetime import datetime
import netifaces
from manuf import manuf
import os
import csv 

init(autoreset=True)  

# ---------------- Argument Parser ----------------
parser = argparse.ArgumentParser(description="Network Scanner to find active devices on the network.")
# add argument
parser.add_argument("-t", "--target", required=True, help="Target IP range. Example: 192.168.1.0/24")
parser.add_argument("--timeout", type=int, default=7, help="Timeout in seconds for ARP requests. Default is 7.")
parser.add_argument("--fast", action='store_true', help="Skip OS detection and only get MAC vendor.")
parser.add_argument("-o", "--output", help="Save results to a file (CSV format)")
                   
# Reading and analyzing arguments
args = parser.parse_args()

# ------------------- Configuration -------------------
gateway_ip = args.target
timeout_val = args.timeout
fast_mode = args.fast
output_file = args.output
# -----------------------------------------------------

if os.geteuid() != 0:
    print(Fore.RED + "[!] Please run this script as root (sudo).")
    exit()

mac_parser = manuf.MacParser()


def get_active_interface():
    """Return the default active network interface name"""
    gws = netifaces.gateways()
    default_gateway = gws.get('default')
    if default_gateway and netifaces.AF_INET in default_gateway:
        return default_gateway[netifaces.AF_INET][1]
    return "Unknown"

def print_banner(interface):
    """Display scan information banner"""
    print(Fore.CYAN + "\n" + "="*70)
    print(Fore.GREEN + " "*20 + "HIGH ACCURACY NETWORK SCANNER")
    print(Fore.CYAN + "="*70)
    print(Fore.YELLOW + f"[*] GitHub    : https://github.com/yourusername/high-accuracy-network-scanner")
    print(Fore.YELLOW + f"[*] Project   : High Accuracy Network Scanner")
    print(Fore.YELLOW + f"[*] User      : {getpass.getuser()}")
    print(Fore.YELLOW + f"[*] Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.YELLOW + f"[*] Target    : {gateway_ip}")
    print(Fore.YELLOW + f"[*] Timeout   : {timeout_val} second(s)")
    print(Fore.YELLOW + f"[*] Interface : {interface}")
    print(Fore.YELLOW + f"[*] Fast Mode : {'Enabled' if fast_mode else 'Disabled'}")
    print(Fore.CYAN + "="*70 + "\n")



def detect_device_type(ip, mac):
    """Detect device type and vendor using nmap OS detection and MAC database"""
    try:
        details = []

        # Get MAC vendor
        vendor = mac_parser.get_manuf(mac)
        if vendor:
            details.append(f"Vendor: {vendor}")

        # Only do OS scan if not in fast mode
        if not fast_mode:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments='-O -sS -T4 --osscan-guess')
            if ip in nm.all_hosts():
                host = nm[ip]
                if 'osmatch' in host and host['osmatch']:
                    best_match = host['osmatch'][0]
                    os_name = best_match['name']
                    os_accuracy = best_match['accuracy']
                    details.append(f"{os_name} (Accuracy: {os_accuracy}%)")

        return " | ".join(details) if details else "Unknown Device"

    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not detect device type for {ip}: {e}")
        return "Unknown Device"


# ---------------- Network Scan ----------------
def scan(ip, timeout):
    """Scan network for active devices using ARP requests"""
    print(Fore.CYAN + "[*] Sending ARP requests...")

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = scapy.ARP(pdst=ip)
    # print(arp_request.show())
    arp_request_broadcast = broadcast / arp_request
    # Return a couple (answered, unanswered)
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)

    print(Fore.GREEN + f"[+] ARP replies received: {len(answered_list)}")
    print(Fore.YELLOW + f"[!] No response from: {len(unanswered_list)} devices\n")

    # ------
    devices = []
    for sent, received in answered_list:
        # print(Fore.CYAN + f"\r[*] Processing device /{len(answered_list)}...", end="")
        device = {
            "ip": received.psrc, 
            "mac": received.hwsrc,
            "type": detect_device_type(received.psrc, received.hwsrc)
            }
        devices.append(device)
        # print("\n" + Fore.GREEN + "[+] Device information collected")
    return devices



# ---------------- Print Results ----------------
def print_result(devices):
    """Print scan results in formatted table"""
    print(Fore.CYAN + "\n[*] Scanning results:\n")
    print(Fore.YELLOW + "IP Address".ljust(16) + "MAC Address".ljust(20) + "Device Type")
    print(Fore.YELLOW + "-" * 60)
    for device in devices:
        # print(f"{Fore.CYAN}{device['ip']:<15} {Fore.GREEN}{device['mac']} {Fore.MAGENTA}{device['type']}")
        print(f"{Fore.CYAN}{device['ip'].ljust(16)} {Fore.GREEN}{device['mac'].ljust(20)} {Fore.MAGENTA}{device['type']}")
    print(f"\n{Fore.YELLOW}[+] Number of devices detected: {len(devices)}")


def save_results(devices, filename):
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "MAC Address", "Device Type"])
            for device in devices:
                writer.writerow([device['ip'], device['mac'], device['type']])
        print(Fore.GREEN + f"\n[+] Results saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[!] Could not save results: {e}")

# ---------------- Main Function ----------------
def main():
    try:
        # Get the name of the active network interface
        interface_name = get_active_interface()
        if interface_name == "Unknown":
            print(Fore.RED + "[!] Could not detect the active network interface.")
            return

        # Print banner and general information
        print_banner(interface_name)

        print(Fore.CYAN + "[*] Scanning for active devices on the network...\n")

        # Record the scan start time
        start_time = time.time()

        # Perform ARP scan
        scan_result = scan(gateway_ip, timeout_val)

        # Print the scan results
        print_result(scan_result)

        # Save the results to a CSV file if specified
        if output_file:
            save_results(scan_result, output_file)

        # Calculate and print the scan duration
        scan_time = time.time() - start_time
        print(Fore.YELLOW + f"\n[✓] Scan completed in {scan_time:.2f} seconds.\n")

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Scan interrupted by user (Ctrl+C). Restoring network (ARP tables)...")
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error during execution: {e}")


# ---------------- Run App ---------------- #

if __name__ == "__main__":
    main()
    