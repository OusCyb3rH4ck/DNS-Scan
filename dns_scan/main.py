#!/usr/bin/env python3

from colorama import Fore, Style
from tabulate import tabulate
from pwn import *
import requests, argparse, subprocess, signal, sys, time
from concurrent.futures import ThreadPoolExecutor

def def_handler(sig, frame):
    print(f"\n\n{Fore.RED}[!] Exiting...{Style.RESET_ALL}\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def fetch_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        domains = set()
        for entry in data:
            names = entry['name_value'].split('\n')
            for name in names:
                domains.add(name.strip().lower())
        return list(domains)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching domains from crt.sh: {e}")
        return []

def fetch_subdomains_from_hackertarget(domain):
    response = requests.get(f'https://api.hackertarget.com/hostsearch/?q={domain}')
    if response.status_code == 200:
        return [line.split(',')[0] for line in response.text.splitlines()]
    return []

def fetch_subdomains_from_tool(command):
    try:
        result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        return result.communicate()[0].splitlines()
    except Exception as e:
        print(f"Error fetching domains with {command[0]}: {e}")
        return []

def show_statistics(subdomains_crtsh, subdomains_hackertarget, subdomains_assetfinder, subdomains_findomain, subdomains_subfinder, output_file=None):
    stats = [
        [f"{Fore.CYAN}crt.sh{Style.RESET_ALL}", len(subdomains_crtsh)],
        [f"{Fore.CYAN}HackerTarget{Style.RESET_ALL}", len(subdomains_hackertarget)],
        [f"{Fore.CYAN}AssetFinder{Style.RESET_ALL}", len(subdomains_assetfinder)],
        [f"{Fore.CYAN}Findomain{Style.RESET_ALL}", len(subdomains_findomain)],
        [f"{Fore.CYAN}SubFinder{Style.RESET_ALL}", len(subdomains_subfinder)],
        [f"{Fore.GREEN+Style.BRIGHT}UNIQUE TOTAL{Style.RESET_ALL}", f"{Style.BRIGHT+Fore.LIGHTGREEN_EX}{len(set(subdomains_crtsh + subdomains_hackertarget + subdomains_assetfinder + subdomains_findomain + subdomains_subfinder))}{Style.RESET_ALL}"]
    ]
    
    if output_file:
        stats.append([f"{Fore.YELLOW}Saved to file{Style.RESET_ALL}", output_file])
    
    print("\n")
    print(tabulate(stats, headers=[f"{Fore.MAGENTA+Style.BRIGHT}SOURCE{Style.RESET_ALL}", f"{Fore.MAGENTA+Style.BRIGHT}SUBDOMAINS{Style.RESET_ALL}"], tablefmt="fancy_grid"))

def main():
    parser = argparse.ArgumentParser(description='Get all subdomains of a domain passively using various tools and APIs.')
    parser.add_argument('-d', '--domain', required=True, help='Domain to analyze')
    parser.add_argument('-o', '--output', help='Output file to save the subdomains')
    args = parser.parse_args()

    print("\n")
    toolbar = log.progress(f"{Fore.LIGHTYELLOW_EX}Fetching subdomains for {Fore.MAGENTA}{args.domain}{Style.RESET_ALL}")
    toolbar.status("Please, wait a moment...")

    with ThreadPoolExecutor() as executor:
        future_crtsh = executor.submit(fetch_subdomains_from_crtsh, args.domain)
        future_hackertarget = executor.submit(fetch_subdomains_from_hackertarget, args.domain)

        future_assetfinder = executor.submit(fetch_subdomains_from_tool, ['assetfinder', '--subs-only', args.domain])
        future_findomain = executor.submit(fetch_subdomains_from_tool, ['findomain', '-t', args.domain])
        future_subfinder = executor.submit(fetch_subdomains_from_tool, ['subfinder', '-silent', '-d', args.domain])

        subdomains_crtsh = future_crtsh.result()
        subdomains_hackertarget = future_hackertarget.result()
        subdomains_assetfinder = future_assetfinder.result()
        subdomains_findomain = future_findomain.result()
        subdomains_subfinder = future_subfinder.result()

    subdomains = sorted(set(subdomains_crtsh + subdomains_hackertarget + subdomains_assetfinder + subdomains_findomain + subdomains_subfinder))

    toolbar.success(f"{Fore.GREEN+Style.BRIGHT}All subdomains have been fetched successfully!{Style.RESET_ALL}")
    time.sleep(5)
    print("\n")
    
    if not subdomains:
        print(f'No subdomains found for {args.domain}')
        return

    exclude_output = ['A error has occurred while querying the Crtsh', 'A error has occurred while connecting', 'Searching in the', 'Target ==>', 'Job finished', 'Good luck Hax0r', 'API count exceeded']

    for subdomain in sorted(subdomains):
        if not any(exclude in subdomain for exclude in exclude_output):
            print(subdomain)
    
    if args.output:
        with open(args.output, 'w') as f:
            for subdomain in sorted(subdomains):
                if not any(exclude in subdomain for exclude in exclude_output):
                    f.write(subdomain + '\n')

    show_statistics(subdomains_crtsh, subdomains_hackertarget, subdomains_assetfinder, subdomains_findomain, subdomains_subfinder, args.output)

if __name__ == '__main__':
    main()
