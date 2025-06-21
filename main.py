import colorama
from colorama import *
import os
import ipinfo
import requests
import time
import socket
import subprocess
import ipaddress
import phonenumbers
from phonenumbers import geocoder, carrier
import hashlib
import base64
import itertools

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


def username_tracker():
    check_os()
    print(Fore.CYAN + banner)
    username = input(Fore.CYAN + "\nEnter the username to check: " + Style.RESET_ALL)

    print(Fore.CYAN + f"\n[+] Checking username '{username}' across multiple sites...\n")

    sites = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}/",
        "Vimeo": f"https://vimeo.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "AskFM": f"https://ask.fm/{username}",
        "Telegram": f"https://t.me/{username}",
        "Replit": f"https://replit.com/@{username}",
        "Kaggle": f"https://www.kaggle.com/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "Keybase": f"https://keybase.io/{username}",
        "Codeforces": f"https://codeforces.com/profile/{username}",
        "Wattpad": f"https://www.wattpad.com/user/{username}",
        "Roblox": f"https://www.roblox.com/user.aspx?username={username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Blogger": f"https://{username}.blogspot.com",
        "Snapchat": f"https://www.snapchat.com/add/{username}"
    }

    headers = {"User-Agent": "Mozilla/5.0"}
    for site, url in sites.items():
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Found on {site}: {url}")
            elif response.status_code == 404:
                print(Fore.RED + f"[-] Not found on {site}")
            else:
                print(Fore.YELLOW + f"[?] Unknown status on {site} ({response.status_code})")
        except requests.RequestException:
            print(Fore.YELLOW + f"[!] Error checking {site}")

    return_to_menu()


def email_lookup():
    check_os()
    print(Fore.CYAN + banner)
    email = input(Fore.CYAN + "\nEnter the email address to check: " + Style.RESET_ALL).strip()
    api_key = input(Fore.YELLOW + "\nEnter your HaveIBeenPwned API key: " + Style.RESET_ALL).strip()

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "Z9ATools-EmailLookup/1.0",
    }

    print(Fore.CYAN + f"\n[+] Checking data breaches for: {email}\n")
    time.sleep(1.6)  # 1.6 rate limit

    try:
        response = requests.get(url, headers=headers, params={"truncateResponse": False})

        if response.status_code == 200:
            breaches = response.json()
            print(Fore.GREEN + f"[+] {email} was found in {len(breaches)} breach(es):\n")
            for b in breaches:
                print(Fore.YELLOW + f"- {b['Name']} ({b['Domain']}) | Breach date: {b['BreachDate']}")
        elif response.status_code == 404:
            print(Fore.RED + f"[-] No breaches found for {email}.")
        elif response.status_code == 401:
            print(Fore.RED + "[!] Invalid API key.")
        elif response.status_code == 429:
            print(Fore.RED + "[!] Rate limited. Please wait before trying again.")
        else:
            print(Fore.RED + f"[!] Unexpected error: HTTP {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

    return_to_menu()



def phone_lookup():
    check_os()
    print(Fore.CYAN + banner)
    number = input(Fore.CYAN + "\nEnter the phone number (with country code, e.g. +33612345678): " + Style.RESET_ALL).strip()

    try:
        parsed = phonenumbers.parse(number, None)

        if not phonenumbers.is_possible_number(parsed) or not phonenumbers.is_valid_number(parsed):
            print(Fore.RED + "[!] Invalid phone number.")
        else:
            region = geocoder.description_for_number(parsed, "en")
            operator = carrier.name_for_number(parsed, "en")
            country_code = parsed.country_code
            national_number = parsed.national_number

            print(Fore.GREEN + "\n[+] Phone Number Information:\n")
            print(Fore.CYAN + f"• Country Code : +{country_code}")
            print(f"• Carrier      : {operator if operator else 'Unknown'}")
            print(f"• Region       : {region if region else 'Unknown'}")
            print(f"• Number       : {national_number}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

    return_to_menu()


def encode_decode():
    check_os()
    print(Fore.CYAN + banner)
    print(Fore.CYAN + "[1] Encode (hash/Base64/Hex)")
    print(Fore.CYAN + "[2] Decode (Base64/Hex)")
    choice = input(Fore.CYAN + "\nChoose option: " + Style.RESET_ALL)

    if choice == '1':
        data = input(Fore.CYAN + "\nEnter text to encode: " + Style.RESET_ALL).encode()
        print(Fore.CYAN + "\nChoose encoding type:")
        print("[1] MD5")
        print("[2] SHA1")
        print("[3] SHA256")
        print("[4] SHA512")
        print("[5] Base64")
        print("[6] Hex")
        enc_choice = input(Fore.CYAN + "\nYour choice: " + Style.RESET_ALL)

        if enc_choice == '1':
            result = hashlib.md5(data).hexdigest()
        elif enc_choice == '2':
            result = hashlib.sha1(data).hexdigest()
        elif enc_choice == '3':
            result = hashlib.sha256(data).hexdigest()
        elif enc_choice == '4':
            result = hashlib.sha512(data).hexdigest()
        elif enc_choice == '5':
            result = base64.b64encode(data).decode()
        elif enc_choice == '6':
            result = data.hex()
        else:
            print(Fore.RED + "[!] Invalid encoding choice.")
            return_to_menu()
            return

        print(Fore.GREEN + f"\nEncoded result:\n{result}")

    elif choice == '2':
        data = input(Fore.CYAN + "\nEnter text to decode: " + Style.RESET_ALL)
        print(Fore.CYAN + "\nChoose decoding type:")
        print("[1] Base64")
        print("[2] Hex")
        dec_choice = input(Fore.CYAN + "\nYour choice: " + Style.RESET_ALL)

        try:
            if dec_choice == '1':
                result = base64.b64decode(data).decode(errors='replace')
            elif dec_choice == '2':
                result = bytes.fromhex(data).decode(errors='replace')
            else:
                print(Fore.RED + "[!] Invalid decoding choice.")
                return_to_menu()
                return
            print(Fore.GREEN + f"\nDecoded result:\n{result}")
        except Exception as e:
            print(Fore.RED + f"[!] Error decoding: {e}")

    else:
        print(Fore.RED + "[!] Invalid option.")

    return_to_menu()



def subdomain_finder():
    check_os()
    print(Fore.CYAN + banner)
    print(Fore.CYAN + "Subdomain Finder (crt.sh)" + Style.RESET_ALL)
    domain = input(Fore.CYAN + "\nEnter the main domain (example : example.com): " + Style.RESET_ALL).strip()

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(Fore.CYAN + f"\nQuerying crt.sh for subdomains of {domain}...\n" + Style.RESET_ALL)

    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            print(Fore.RED + f"Error fetching data from crt.sh (status {resp.status_code})" + Style.RESET_ALL)
            return

        data = resp.json()
        subdomains = set()

        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip()
                if sub.endswith(domain):
                    subdomains.add(sub.lower())

        if not subdomains:
            print(Fore.RED + "No subdomains found." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"Found {len(subdomains)} unique subdomains:\n" + Style.RESET_ALL)
            for sd in sorted(subdomains):
                print(Fore.GREEN + sd + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"Error during request or parsing: {e}" + Style.RESET_ALL)

    return_to_menu()


def wordlist_gen_mrrobot():
    check_os()
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "\n[~] Wordlist Generator — Personal Info Based\n" + Style.RESET_ALL)

    first = input("First name: ").strip()
    last = input("Last name: ").strip()
    nickname = input("Nickname / username: ").strip()
    birth_year = input("Year of birth (e.g. 2012): ").strip()
    birth_day = input("Day and month (e.g. 1204 or April12): ").strip()
    pet = input("Pet name: ").strip()
    partner = input("Partner name: ").strip()
    city = input("City / hometown: ").strip()
    company = input("Company / school: ").strip()
    fav = input("Favorite word / phrase: ").strip()

    inputs = [first, last, nickname, birth_year, birth_day, pet, partner, city, company, fav]
    elements = [e for e in inputs if e]

    def case_variants(w):
        return {w.lower(), w.upper(), w.capitalize()}

    def partials(w):
        return {w[:i] for i in range(1, len(w)+1)}

    def combine_all(elements, max_len=4):
        result = set()
        for r in range(1, max_len+1):
            for combo in itertools.permutations(elements, r):
                joined = ''.join(combo)
                result.add(joined)
        return result

    suffixes = ['123', '1234', '007', '!', '@', '?', '#']
    if birth_year:
        suffixes += [birth_year, birth_year[-2:], '19'+birth_year[-2:], '20'+birth_year[-2:]]

    base_parts = set()
    for word in elements:
        base_parts.update(partials(word))
        base_parts.add(word)

    all_variants = set()
    for part in base_parts:
        all_variants.update(case_variants(part))

    combined_words = combine_all(all_variants, max_len=3)

    full_set = set()
    for word in combined_words:
        full_set.add(word)
        for suf in suffixes:
            full_set.add(word + suf)
            full_set.add(suf + word)

    full_set = {w for w in full_set if len(w) >= 4}

    with open("wordlist.txt", "w", encoding="utf-8") as f:
        for word in sorted(full_set):
            f.write(word + "\n")

    print(Fore.GREEN + f"\n[✓] Wordlist saved as 'wordlist.txt' with {len(full_set)} entries.")
    return_to_menu()



def main():
    check_os()
    print(Fore.CYAN + banner)
    print(Fore.WHITE + "            [" + Fore.CYAN + "1" + Fore.WHITE + "]" + Fore.CYAN + " IP Lookup" + "              " + Fore.WHITE + "[" + Fore.CYAN + "8" + Fore.WHITE + "]" + Fore.CYAN + " Encode/Decode")
    print(Fore.WHITE + "            [" + Fore.CYAN + "2" + Fore.WHITE + "]" + Fore.CYAN + " Port Scanner" + "           " + Fore.WHITE + "[" + Fore.CYAN + "9" + Fore.WHITE + "]" + Fore.CYAN + " Subdomain Finder")
    print(Fore.WHITE + "            [" + Fore.CYAN + "3" + Fore.WHITE + "]" + Fore.CYAN + " Scan IP Range" + "          " + Fore.WHITE + "[" + Fore.CYAN + "10" + Fore.WHITE + "]" + Fore.CYAN + " Wordlist Generator")
    print(Fore.WHITE + "            [" + Fore.CYAN + "4" + Fore.WHITE + "]" + Fore.CYAN + " IP Pinger")
    print(Fore.WHITE + "            [" + Fore.CYAN + "5" + Fore.WHITE + "]" + Fore.CYAN + " Username Tracker")
    print(Fore.WHITE + "            [" + Fore.CYAN + "6" + Fore.WHITE + "]" + Fore.CYAN + " Email Lookup (HIBP)")
    print(Fore.WHITE + "            [" + Fore.CYAN + "7" + Fore.WHITE + "]" + Fore.CYAN + " Phone Lookup")
    menu = input(Fore.CYAN + "\n\nroot@Z9ATools:~# " + Style.RESET_ALL)

    if menu == '1':
        iplookup()
    elif menu == '2':
        port_scanner()
    elif menu == '3':
        scan_ip_range()
    elif menu == '4':
        ip_pinger()
    elif menu == '5':
        username_tracker()
    elif menu == '6':
        email_lookup()
    elif menu == '7':
        phone_lookup()
    elif menu == '8':
        encode_decode()
    elif menu == '9':
        subdomain_finder()
    elif menu == '10':
        wordlist_gen_mrrobot()
    else:
        print(Fore.RED + "\n[!] Invalid option.")
        time.sleep(1)
        main()

if __name__ == "__main__":
    main()
