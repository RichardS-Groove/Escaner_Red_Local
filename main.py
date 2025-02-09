#!/usr/bin/env python3


"""

Created by Benjamin
02/2025

"""



import os
import json
import requests
import socket
import netifaces
import warnings
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table

warnings.filterwarnings("ignore", category=SyntaxWarning)

console = Console()

BANNER = """
[bold green]

888     888          d8b      888             d8888 8888888b.  8888888b.  
888     888          Y8P      888            d88888 888   Y88b 888   Y88b 
888     888                   888           d88P888 888    888 888    888 
Y88b   d88P  .d88b.  888  .d88888          d88P 888 888   d88P 888   d88P 
 Y88b d88P  d88""88b 888 d88" 888         d88P  888 8888888P"  8888888P"  
  Y88o88P   888  888 888 888  888        d88P   888 888 T88b   888        
   Y888P    Y88..88P 888 Y88b 888       d8888888888 888  T88b  888        
    Y8P      "Y88P"  888  "Y88888      d88P     888 888   T88b 888   
     
[/bold green]
"""

LEGAL_NOTICE = """
[bold yellow]
[!] LEGAL DISCLAIMER:
This program is intended for educational and cybersecurity research purposes only.
Unauthorized network scanning may be illegal and is strictly prohibited.
The author assumes no responsibility for any misuse or damage caused by this software.
Use it only on networks where you have explicit permission.

By running this program, you agree to comply with all applicable laws and regulations.
[/bold yellow]
"""

iot_vendors = ["TP-Link", "Xiaomi", "Ring", "Arlo", "Nest", "Philips", "Eufy", "Netgear", "Ubiquiti", "Sonoff"]

def get_local_network():
    """Retrieves the current machine's IP address and subnet in CIDR notation."""
    interfaces = netifaces.interfaces()

    for interface in interfaces:
        if interface.startswith("eth") or interface.startswith("wlan"):  
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip_address = ip_info['addr']
                netmask = ip_info['netmask']
                cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))  
                return f"{ip_address}/{cidr}"

    return None  

def scan_network(network):
    """Sends ARP requests to discover active devices on the network."""
    console.print(f"[bold cyan]Scanning the network {network}...[/bold cyan]")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})  

    return devices

def get_vendor(mac):
    """Queries the macaddress.io API to retrieve the device manufacturer."""
    try:
        url = f"https://api.macaddress.io/v1?apiKey=at_dDDVtw5fHbgPmgEtENWJQLDK7rvJo&output=json&search={mac}"
        response = requests.get(url, timeout=5)  
        
        if response.status_code == 200:
            data = response.json()
            return data.get("vendorDetails", {}).get("companyName", "Unknown Vendor")
    except requests.exceptions.RequestException:
        pass  
    
    return "Unknown Vendor"


def scan_ports(ip):
    """Scans the most common ports on a given IP."""
    open_ports = []
    common_ports = [22, 80, 443, 3389, 53, 445]  

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)  
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except:
            pass
    
    return open_ports

def is_iot_device(vendor):
    """Checks if a device belongs to a known IoT manufacturer."""
    return any(vendor.lower() in iot.lower() for iot in iot_vendors)

def parallel_processing(devices):
    """Uses multithreading to speed up vendor lookup and port scanning."""
    with ThreadPoolExecutor(max_workers=10) as executor:
        for device in devices:
            device['vendor'] = executor.submit(get_vendor, device['mac']).result()
            device['open_ports'] = executor.submit(scan_ports, device['ip']).result()

def display_results(devices):
    """Displays the scan results in a structured table."""
    table = Table(title="IoT Scanner Results", show_lines=True)
    table.add_column("IP Address", style="cyan", justify="center")
    table.add_column("MAC Address", style="magenta", justify="center")
    table.add_column("Vendor", style="green", justify="center")
    table.add_column("Open Ports", style="yellow", justify="center")
    table.add_column("IoT Device", style="red", justify="center")

    for device in devices:
        iot_status = "Yes" if is_iot_device(device["vendor"]) else "No"
        table.add_row(device['ip'], device['mac'], device['vendor'], ", ".join(map(str, device['open_ports'])), iot_status)

    console.print(table)

def export_results(devices):
    """Saves the scan results to JSON format."""
    os.makedirs("results", exist_ok=True)  
    
    with open("results/devices.json", "w") as jsonfile:
        json.dump(devices, jsonfile, indent=4)
    
    console.print("[bold green]Results saved to results/devices.json[/bold green]")

def main():
    console.print(BANNER)  
    console.print(LEGAL_NOTICE)  

    console.print("\n[1] Scan the current IP address")
    console.print("[2] Enter a network range manually")
    choice = input("\nChoose an option (1/2): ").strip()

    if choice == "1":
        network = get_local_network()
        if network:
            console.print(f"[bold cyan]Detected network: {network}[/bold cyan]")
        else:
            console.print("[bold red]Failed to detect network![/bold red]")
            return
    else:
        network = input("Enter the network range (e.g., 192.168.1.0/24): ").strip()

    devices = scan_network(network)
    parallel_processing(devices)
    display_results(devices)

    if input("Do you want to export results? (yes/no): ").strip().lower() == "yes":
        export_results(devices)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Script interrupted by user (CTRL+C). Exiting...[/bold red]")
