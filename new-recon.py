import argparse
import re
import csv
import ipaddress
import signal
import os
import socket
import subprocess
import sys
import time
import json
from collections import defaultdict
import dns.resolver

def expand_cidr(cidr):
    try:
        return [str(ip) for ip in ipaddress.ip_network(cidr, strict=False)]
    except ValueError:
        return []

def process_input_file(input_file_path):
    input_ips = set()
    with open(input_file_path) as f:
        for line in f:
            line = line.strip()
            if '/' in line:
                input_ips.update(expand_cidr(line))
            else:
                input_ips.add(line)
    return input_ips

def resolve_subdomains(subdomains, target_domain):
    resolved_subdomains = defaultdict(set)
    for subdomain in subdomains:
        try:
            ip_addresses = set(socket.gethostbyname_ex(subdomain.rstrip('.'))[2])
            for ip in ip_addresses:
                resolved_subdomains[ip].add(subdomain)
        except (socket.gaierror, ValueError):
            print(f"Error resolving subdomain {subdomain}: host not found")
    return resolved_subdomains

def process_input_ips(input_ips, resolved_subdomains):
    domains = []
    for ip in input_ips:
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            continue

        if str(ip) in resolved_subdomains:
            domain_info = {
                'ip': ip,
                'subdomain': ', '.join(resolved_subdomains[str(ip)]),
                'open_ports': None,
                'application': []
            }
            domains.append(domain_info)
        else:
            domain_info = {
                'ip': ip,
                'subdomain': '',
                'open_ports': 'N/A',
                'application': []
            }
            domains.append(domain_info)
    return domains

def scan_ports(ip, skip_scans=False):
    if skip_scans:
        return 'N/A'  # never iterated over in write_csv

    print(f'Scanning {ip}...')
    open_ports = set()
    with open(os.devnull, 'w') as devnull:
        result = subprocess.run(['nmap', '-Pn', '-p', '1-65535', '--host-timeout', '45m', str(ip)],
                                stdout=subprocess.PIPE, stderr=devnull, encoding='utf-8')
        lines = result.stdout.splitlines()
        for line in lines:
            if 'open' in line:
                port = int(line.split('/')[0].strip())
                open_ports.add(port)
    return open_ports

def run_nuclei(domain, port):
    try:
        print(f'Running nuclei on {domain}:{port}...')
        command = "nuclei -silent -nc -t exposed-panels/ -t technologies/ -u {0}:{1}".format(domain, port)
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        output = output.decode('utf-8').strip()
        print(output)
        if output:
            return output
        else:
            return ''
    except subprocess.CalledProcessError as e:
        return {'error': e.output.decode('utf-8')}
    except KeyboardInterrupt:
        print(f"\nNuclei scan on {domain}:{port} was interrupted by user.")
        return ''

def resolve_subdomains(subdomains, target_domain):
    resolved_subdomains = defaultdict(set)
    for subdomain in subdomains:
        non_target_cname = set()  # Initialize the variable here
        try:
            cname_records = set()
            try:
                cname_answers = dns.resolver.resolve(subdomain.rstrip('.'), 'CNAME')
            except dns.resolver.NoAnswer:
                cname_answers = []
            except dns.resolver.Timeout:
                cname_answers = []
                print(f"Error resolving subdomain {subdomain}: Name Server Timeout")
            except dns.resolver.NoNameservers:
                cname_answers = []
                print(f"Error resolving subdomain {subdomain}: No Nameservers/DNSSEC Fail")
            for cname in cname_answers:
                cname_records.add(str(cname.target))

            for cname in cname_records:
                if not cname.endswith(target_domain):
                    non_target_cname.add(cname)

        except (dns.resolver.NXDOMAIN, ValueError):
            print(f"Error resolving subdomain {subdomain}: host not found")
        if non_target_cname:
            for cname in non_target_cname:
                resolved_subdomains[cname].add(subdomain)
        else:
            try:
                ip_addresses = set(socket.gethostbyname_ex(subdomain.rstrip('.'))[2])
                for ip in ip_addresses:
                    resolved_subdomains[ip].add(subdomain)
            except (socket.gaierror, ValueError):
                print(f"Error resolving subdomain {subdomain}: host not found")
    return resolved_subdomains


def scan_domain(domain, input_ips, skip_scans):
    print(f'Enumerating subdomains for \'{domain}\' with subfinder...')
    with open(os.devnull, 'w') as devnull:
        subdomains = set(subprocess.check_output(['subfinder', '-d', domain, '-silent'],
                                                  stderr=devnull, encoding='utf-8').split())

    print(f'Found {len(subdomains)} subdomains for \'{domain}\'')

    # check for wildcard dns
    wildcard_detected = False
    try:
        domain_ips = set(socket.gethostbyname_ex(f"randomstring700000.{domain.rstrip('.')}")[2])
        random_subdomain_ips = set(socket.gethostbyname_ex(f"randomstring123.{domain.rstrip('.')}")[2])
        if domain_ips == random_subdomain_ips:
            wildcard_detected = True
    except (socket.gaierror, ValueError):
        pass

    if wildcard_detected:
       print('Wildcard DNS detected. Running gobuster with wildcard option...')
       with open(os.devnull, 'w') as devnull:
            gobuster_output = subprocess.check_output(['gobuster', 'dns', '-d', f'{domain}', '-o', '/dev/null', '--wildcard', '-w', './SecLists/Discovery/DNS/subdomains-top1million-20000.txt', '-q', '-r', '1.0.0.1'], stderr=devnull, encoding='utf-8')
       gobuster_lines = [line.strip() for line in gobuster_output.split('\n') if line.strip()]
       matching_lines = [line for line in gobuster_lines if line.endswith(domain)]
       prefix = "\x1b[2KFound: "
       cleaned_lines = [line.strip()[len(prefix):] for line in matching_lines if line.strip().startswith(prefix)]
       # Convert the cleaned lines to a set of subdomains and return it
       subdomains = set(cleaned_lines)
    else:
       # run gobuster to get more subdomains
       print(f'Running gobuster on \'{domain}\'...')
       with open(os.devnull, 'w') as devnull:
            gobuster_output = subprocess.check_output(['gobuster', 'dns', '-d', f'{domain}', '-o', '/dev/null', '-w', './SecLists/Discovery/DNS/subdomains-top1million-5000.txt', '-q', '-r', '1.0.0.1'], stderr=devnull, encoding='utf-8')
       gobuster_lines = [line.strip() for line in gobuster_output.split('\n') if line.strip()]
       matching_lines = [line for line in gobuster_lines if line.endswith(domain)]
       prefix = "\x1b[2KFound: "
       cleaned_lines = [line.strip()[len(prefix):] for line in matching_lines if line.strip().startswith(prefix)]
       # Convert the cleaned lines to a set of subdomains and return it
       gobuster_subdomains = set(cleaned_lines)
       subdomains |= gobuster_subdomains


    subdomains = sorted(set(subdomains))

    resolved_subdomains = resolve_subdomains(subdomains, domain)

    cnames = {}
    ips = {}
    for k, v in resolved_subdomains.items():
        try:
            ip = ipaddress.ip_address(k)
            if ip.is_global:
                ips[k] = v
        except ValueError:
            cnames[k] = v

    ips = set(resolved_subdomains.keys()) | input_ips

    print('Running port scan on IPs...')
    domains = []
    #print ("IPs:")
    for ip in ips:
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            continue
        open_ports = scan_ports(ip, skip_scans)
        #print (resolved_subdomains.get(str(ip), []))
        for subdomain in resolved_subdomains.get(str(ip), []):
            #print ("subdomain:")
            #print (subdomain)
            #print ("ip:")
            #print (ip)
            #print ("open ports:")
            #print (open_ports)
            if open_ports:
                domain_info = {
                    'ip': ip,
                    'subdomain': subdomain,
                    'open_ports': open_ports,
                    'application': []
                }
            else:
                domain_info = {
                    'ip': ip,
                    'subdomain': subdomain,
                    'open_ports': set(),   # was None
                    'application': []
                }
            #print ("domain_info:")
            #print (domain_info)
            domains.append(domain_info)
            
        domains.extend(process_input_ips(input_ips, resolved_subdomains))

    for cname, subdomains in cnames.items():
        domain_info = {
            'ip': cname,
            'subdomain': ', '.join(subdomains),
            'open_ports': None,
            'application': []
        }
        domains.append(domain_info)

    if not skip_scans:
        print('Running nuclei scans...')
        for domain in domains:
            if domain['open_ports'] and domain['open_ports'] != 'N/A':
                for port in domain['open_ports']:
                    if isinstance(port, int):  # Check if port is an integer
                        target = f"{domain['subdomain']}:{port}"
                        application = run_nuclei(domain=domain['subdomain'], port=port)
                        domain['application'].append(application)

    #if output_file:
    #    write_csv(output_file, domains)

    return domains

def scan_domains(domains, input_ips, skip_scans):
    all_domain_results = []
    for domain in domains:
        domain_results = scan_domain(domain, input_ips, skip_scans)
        all_domain_results.extend(domain_results)

    return all_domain_results

def write_csv(output_file, domains):
    with open(output_file, 'w', newline='\n') as csvfile:
        fieldnames = ['Domain', 'IP', 'Open Ports', 'Application']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # group subdomains by IP address or CNAME record
        subdomains_by_ip = {}
        for domain in domains:
            ip = domain['ip']
            if ip not in subdomains_by_ip:
                subdomains_by_ip[ip] = []
            subdomains_by_ip[ip].append(domain)

        # write to CSV
        for ip, subdomain_list in subdomains_by_ip.items():
            domains_str = ', '.join(sorted(set([d['subdomain'] for d in subdomain_list])))

            # --- Robust open_ports rendering ---
            any_scanned = False
            ports_union = set()
            all_na = True

            for d in subdomain_list:
                op = d.get('open_ports')
                # 'N/A' means not scanned for that entry
                if isinstance(op, str) and op.upper() == 'N/A':
                    continue
                all_na = False  # at least one entry is scanned (set() or set of ports or None)

                if isinstance(op, (set, list, tuple)):
                    any_scanned = True
                    ports_union.update(op)
                elif op is None:
                    any_scanned = True  # scanned but no ports found (older entries)
                else:
                    # handle single ints or odd values defensively
                    try:
                        ports_union.add(int(op))
                        any_scanned = True
                    except Exception:
                        pass

            if all_na:
                open_ports_str = 'N/A'          # everything was skipped
            else:
                if ports_union:
                    open_ports_str = ', '.join(sorted(str(p) for p in ports_union))
                else:
                    open_ports_str = 'None'      # scanned, but no open ports overall

            # Application column (unchanged)
            application = ', '.join(sorted(list(set(
                a for d in subdomain_list for a in d['application'] if a
            ))))
            writer.writerow({'Domain': domains_str, 'IP': ip, 'Open Ports': open_ports_str, 'Application': application})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automated enumeration and reconnaissance tool')
    parser.add_argument('domains', nargs='+', help='The target domains to scan')
    parser.add_argument('-i', '--input', help='A file containing IP addresses and address ranges to scan')
    parser.add_argument('--skip-scans', action='store_true', help='Skip Nmap and Nuclei scans')
    args = parser.parse_args()

    input_ips = process_input_file(args.input) if args.input else set()
    domains = scan_domains(args.domains, input_ips, args.skip_scans)
    output_file = f"{args.domains[0]}_output.csv"  # Uses the first domain for the output file name
    write_csv(output_file, domains)
