import colorama
from colorama import *
import os
import ipinfo
import requests
import time
import socket
import subprocess
import ipaddress

def check_os():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

banner = """

::::::::: ::::::::      :::          ::::::::::: ::::::::   ::::::::  :::        ::::::::  
     :+: :+:    :+:   :+: :+:            :+:    :+:    :+: :+:    :+: :+:       :+:    :+: 
    +:+  +:+    +:+  +:+   +:+           +:+    +:+    +:+ +:+    +:+ +:+       +:+        
   +#+    +#++:++#+ +#++:++#++:          +#+    +#+    +:+ +#+    +:+ +#+       +#++:++#++ 
  +#+           +#+ +#+     +#+          +#+    +#+    +#+ +#+    +#+ +#+              +#+ 
 #+#     #+#    #+# #+#     #+#          #+#    #+#    #+# #+#    #+# #+#       #+#    #+# 
######### ########  ###     ###          ###     ########   ########  ########## ########  
                                             

                    Telegram | t.me/Z9ATools
"""

def return_to_menu():
    print(Style.RESET_ALL)
    choice = input(Fore.CYAN + "\n\n[?] Return to menu? (y/n): " + Style.RESET_ALL).lower()
    if choice == 'y':
        main()
    else:
        print("\n[!] Exiting...")
        time.sleep(1)
        exit()

def iplookup():
    check_os()
    print(Fore.CYAN + banner)
    ipaddr = input(Fore.CYAN + "\nEnter the IP address: " + Style.RESET_ALL)

    handler = ipinfo.getHandler()

    try:
        details = handler.getDetails(ipaddr)
        print(Fore.CYAN + "\n[+] IP Lookup Result:\n")
        print(f"IP Address : {details.ip}")
        print(f"Hostname   : {details.hostname}")
        print(f"City       : {details.city}")
        print(f"Region     : {details.region}")
        print(f"Country    : {details.country}")
        print(f"Location   : {details.loc}")
        print(f"Org        : {details.org}")
        print(f"Timezone   : {details.timezone}")
    except Exception as e:
        print(Fore.RED + f"\n[-] Failed to fetch details: {e}")
    
    return_to_menu()

def port_scanner():
    check_os()
    print(Fore.CYAN + banner)
    target = input(Fore.CYAN + "\nEnter the IP or hostname to scan: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(Fore.RED + "\n[-] Invalid hostname or IP address.")
        return_to_menu()
        return

    print(Fore.CYAN + f"\n[+] Starting scan on {target} ({ip})...\n")
    open_ports = []

    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(Fore.GREEN + f"Port {port} is open")
            open_ports.append(port)
        sock.close()

    if not open_ports:
        print(Fore.YELLOW + "No open ports found in range 1-1024.")
    else:
        print(Fore.CYAN + f"\nScan completed. Open ports: {', '.join(map(str, open_ports))}")

    return_to_menu()


def scan_ip_range():
    check_os()
    print(Fore.CYAN + banner)
    subnet = input(Fore.CYAN + "\nEnter the subnet (e.g. 192.168.1.0/24): " + Style.RESET_ALL)

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print(Fore.RED + "\n[-] Invalid subnet format.")
        return_to_menu()
        return

    print(Fore.CYAN + f"\n[+] Scanning subnet : {subnet}\n")
    alive_hosts = []

    for ip in network.hosts():
        ip_str = str(ip)
        # Ping once (-c 1) on Unix, (-n 1) on Windows
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', '-w', '1000', ip_str] if os.name == 'nt' else ['ping', param, '1', '-W', '1', ip_str]

        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if output.returncode == 0:
                print(Fore.GREEN + f"{ip_str} is alive")
                alive_hosts.append(ip_str)
            else:
                print(Fore.WHITE + f"{ip_str} is unreachable")
        except Exception:
            print(Fore.RED + f"Error pinging {ip_str}")

    if alive_hosts:
        print(Fore.CYAN + f"\nScan complete. Alive hosts : {', '.join(alive_hosts)}")
    else:
        print(Fore.YELLOW + "\nNo alive hosts found.")

    return_to_menu()


def ip_pinger():
    check_os()
    print(Fore.CYAN + banner)
    ip = input(Fore.CYAN + "\nEnter the IP to ping: " + Style.RESET_ALL)

    param = '-n' if os.name == 'nt' else '-c'
    command = ['ping', param, '1', ip]

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(Fore.GREEN + f"\n{ip} is alive")
    else:
        print(Fore.RED + f"\n{ip} is unreachable")

    return_to_menu()


def main():
    check_os()
    print(Fore.CYAN + banner)
    print(Fore.WHITE + "[" + Fore.CYAN + "1" + Fore.WHITE + "]" + Fore.CYAN + " IP Lookup")
    print(Fore.WHITE + "[" + Fore.CYAN + "2" + Fore.WHITE + "]" + Fore.CYAN + " Port Scanner")
    print(Fore.WHITE + "[" + Fore.CYAN + "3" + Fore.WHITE + "]" + Fore.CYAN + " Scan IP Range")
    print(Fore.WHITE + "[" + Fore.CYAN + "4" + Fore.WHITE + "]" + Fore.CYAN + " IP Pinger")
    menu = input(Fore.CYAN + "\n\nroot@Z9ATools:~# " + Style.RESET_ALL)

    if menu == '1':
        iplookup()
    elif menu == '2':
        port_scanner()
    elif menu == '3':
        scan_ip_range()
    elif menu == '4':
        ip_pinger()
    else:
        print(Fore.RED + "\n[!] Invalid option.")
        time.sleep(1)
        main()

if __name__ == "__main__":
    main()
