#!/usr/bin/env python3
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
            if not line:
                continue
            if '/' in line:
                input_ips.update(expand_cidr(line))
            else:
                input_ips.add(line)
    return input_ips

def load_subs_file(subs_file_path):
    """Load user-provided subdomains (one per line). Returns a set."""
    subs = set()
    with open(subs_file_path) as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            subs.add(s)
    return subs

def resolve_subdomains_with_cname_handling(subdomains, target_domain):
    """
    Resolve subdomains: returns mapping key -> set(subdomain)
    key is either IP string or external CNAME target string.
    """
    resolved_subdomains = defaultdict(set)
    for subdomain in subdomains:
        non_target_cname = set()
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
                cname_records.add(str(cname.target).rstrip('.'))

            for cname in cname_records:
                if not cname.endswith(target_domain.rstrip('.')):
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

def process_input_ips(input_ips, resolved_subdomains):
    """
    Build domain entries for IPs that came from the input file.
    - If an input IP is present in resolved_subdomains, attach subdomains and mark open_ports as set().
    - If input IP has no matching subdomain, mark open_ports as 'N/A'.
    """
    domains = []
    for ip in sorted(input_ips):
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            # non-IP: treat as not-scanned
            domains.append({
                'ip': ip,
                'subdomain': '',
                'open_ports': 'N/A',
                'application': []
            })
            continue

        if str(ip_obj) in resolved_subdomains:
            domains.append({
                'ip': ip_obj,
                'subdomain': ', '.join(sorted(resolved_subdomains[str(ip_obj)])),
                'open_ports': set(),
                'application': []
            })
        else:
            domains.append({
                'ip': ip_obj,
                'subdomain': '',
                'open_ports': 'N/A',
                'application': []
            })
    return domains

def scan_ports(ip, skip_scans=False):
    """
    Returns:
      - 'N/A' (string) if skip_scans True
      - set() if nmap ran and there were no open ports
      - set([ports...]) if open ports found
    """
    if skip_scans:
        return 'N/A'

    print(f'Scanning {ip}...')
    open_ports = set()
    with open(os.devnull, 'w') as devnull:
        try:
            result = subprocess.run(
                ['nmap', '-Pn', '-p', '1-65535', '--host-timeout', '1m', str(ip)],
                stdout=subprocess.PIPE, stderr=devnull, encoding='utf-8', check=False
            )
        except FileNotFoundError:
            print("nmap not found in PATH. Skipping scan for", ip)
            return 'N/A'

        lines = result.stdout.splitlines()
        for line in lines:
            parts = line.strip().split()
            if not parts:
                continue
            m = re.match(r'^(\d+)\/', parts[0])
            if m and 'open' in line:
                try:
                    port = int(m.group(1))
                    open_ports.add(port)
                except Exception:
                    pass
    return open_ports

def run_nuclei(domain, port):
    try:
        print(f'Running nuclei on {domain}:{port}...')
        command = "nuclei -silent -nc -t exposed-panels/ -t technologies/ -u {0}:{1}".format(domain, port)
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        try:
            output = output.decode('utf-8').strip()
        except Exception:
            output = ''
        if output:
            print(output)
            return output
        return ''
    except subprocess.CalledProcessError as e:
        try:
            return {'error': e.output.decode('utf-8')}
        except Exception:
            return {'error': str(e)}
    except KeyboardInterrupt:
        print(f"\nNuclei scan on {domain}:{port} was interrupted by user.")
        return ''

def scan_domain(domain, input_ips, subs_override=None, skip_scans=False):
    """
    Scans one parent domain:
      - runs subfinder (unless subs_override provides subdomains)
      - runs gobuster and merges results
      - merges user-provided subs (subs_override) into discovered set and dedupes
      - resolves subdomains (IP or external CNAME targets)
      - scans IPs (unless skip_scans)
      - gathers CNAMES as not-scanned entries
      - returns list of domain_info dicts
    """
    # Load discovered subs (subfinder) first
    print(f'Enumerating subdomains for \'{domain}\' with subfinder...')
    try:
        with open(os.devnull, 'w') as devnull:
            subfinder_out = subprocess.check_output(['subfinder', '-d', domain, '-silent'], stderr=devnull, encoding='utf-8')
            discovered = set(subfinder_out.split())
    except FileNotFoundError:
        print("subfinder not found in PATH. No subfinder results.")
        discovered = set()
    except subprocess.CalledProcessError:
        discovered = set()

    # Merge user-provided subs if given (dedupe against discovered)
    if subs_override:
        # Keep only subs that look like they belong to this scan or explicitly include subs_override anyway
        # We will include subs even if they don't end with the parent domain (keeps existing behaviour)
        discovered |= set(subs_override)

    subdomains = sorted(set(discovered))

    print(f'Found {len(subdomains)} subdomains for \'{domain}\'')

    # check for wildcard dns (same as previous logic)
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
        try:
            with open(os.devnull, 'w') as devnull:
                gobuster_output = subprocess.check_output(
                    ['gobuster', 'dns', '-d', f'{domain}', '-o', '/dev/null', '--wildcard',
                     '-w', './SecLists/Discovery/DNS/subdomains-top1million-20000.txt', '-q', '-r', '1.0.0.1'],
                    stderr=devnull, encoding='utf-8'
                )
                gobuster_lines = [line.strip() for line in gobuster_output.split('\n') if line.strip()]
                matching_lines = [line for line in gobuster_lines if line.endswith(domain)]
                prefix = "\x1b[2KFound: "
                cleaned_lines = [line.strip()[len(prefix):] for line in matching_lines if line.strip().startswith(prefix)]
                subdomains = set(cleaned_lines)
        except Exception:
            pass
    else:
        print(f'Running gobuster on \'{domain}\'...')
        try:
            with open(os.devnull, 'w') as devnull:
                gobuster_output = subprocess.check_output(
                    ['gobuster', 'dns', '-d', f'{domain}', '-o', '/dev/null',
                     '-w', './SecLists/Discovery/DNS/subdomains-top1million-5000.txt', '-q', '-r', '1.0.0.1'],
                    stderr=devnull, encoding='utf-8'
                )
                gobuster_lines = [line.strip() for line in gobuster_output.split('\n') if line.strip()]
                matching_lines = [line for line in gobuster_lines if line.endswith(domain)]
                prefix = "\x1b[2KFound: "
                cleaned_lines = [line.strip()[len(prefix):] for line in matching_lines if line.strip().startswith(prefix)]
                gobuster_subdomains = set(cleaned_lines)
                subdomains = set(subdomains) | gobuster_subdomains
        except Exception:
            pass

    subdomains = sorted(set(subdomains))

    # Now resolve (handles CNAME external targets)
    resolved_subdomains = resolve_subdomains_with_cname_handling(subdomains, domain)

    # Separate cnames vs IPs for later inclusion
    cnames = {}
    ips_map = {}
    for k, v in resolved_subdomains.items():
        try:
            ip_obj = ipaddress.ip_address(k)
            if ip_obj.is_global:
                ips_map[str(k)] = v
        except ValueError:
            cnames[k] = v

    keys_to_scan = set(resolved_subdomains.keys()) | set(input_ips)

    print('Running port scan on IPs...')
    domains = []

    for key in sorted(keys_to_scan):
        if not key:
            continue
        try:
            ip_obj = ipaddress.ip_address(key)
        except ValueError:
            continue

        open_ports = scan_ports(ip_obj, skip_scans)

        mapped_subs = resolved_subdomains.get(str(ip_obj), [])
        if mapped_subs:
            for subdomain in sorted(mapped_subs):
                if isinstance(open_ports, str) and open_ports == 'N/A':
                    domain_info = {
                        'ip': ip_obj,
                        'subdomain': subdomain,
                        'open_ports': 'N/A',
                        'application': []
                    }
                else:
                    domain_info = {
                        'ip': ip_obj,
                        'subdomain': subdomain,
                        'open_ports': open_ports if isinstance(open_ports, set) else set(),
                        'application': []
                    }
                domains.append(domain_info)
        else:
            if str(ip_obj) in input_ips:
                if isinstance(open_ports, str) and open_ports == 'N/A':
                    domain_info = {
                        'ip': ip_obj,
                        'subdomain': '',
                        'open_ports': 'N/A',
                        'application': []
                    }
                else:
                    domain_info = {
                        'ip': ip_obj,
                        'subdomain': '',
                        'open_ports': open_ports if isinstance(open_ports, set) else set(),
                        'application': []
                    }
                domains.append(domain_info)
            else:
                if isinstance(open_ports, set) and open_ports:
                    domains.append({
                        'ip': ip_obj,
                        'subdomain': '',
                        'open_ports': open_ports,
                        'application': []
                    })

    # Add any input-only rows (ensures input IPs are present once)
    domains.extend(process_input_ips(input_ips, resolved_subdomains))

    # Add CNAMES as N/A rows
    for cname_key, subdomains_set in cnames.items():
        domains.append({
            'ip': cname_key,
            'subdomain': ', '.join(sorted(subdomains_set)),
            'open_ports': 'N/A',
            'application': []
        })

    # Nuclei if not skipped
    if not skip_scans:
        print('Running nuclei scans...')
        for d in domains:
            op = d.get('open_ports')
            if isinstance(op, (set, list, tuple)) and op:
                for port in sorted(op):
                    if isinstance(port, int):
                        application = run_nuclei(domain=d['subdomain'] or str(d['ip']), port=port)
                        if application:
                            d['application'].append(application)

    return domains

def scan_domains(domains_list, input_ips, subs_set=None, skip_scans=False):
    """
    domains_list: list of parent domains to scan
    subs_set: global set of user-provided subdomains (we'll include only those that are relevant per parent)
    """
    all_domain_results = []
    # For each parent domain, build a per-domain subset of user-supplied subs:
    for domain in domains_list:
        per_domain_subs = None
        if subs_set:
            if args.subs_include_external:
                # include all user-subs (legacy permissive behaviour)
                per_domain_subs = set(s for s in subs_set if s)
            else:
                # Strict: include only subs that end with the parent domain
                per_domain_subs = set(s for s in subs_set if s and s.rstrip('.').endswith(domain.rstrip('.')))
        domain_results = scan_domain(domain, input_ips, subs_override=per_domain_subs, skip_scans=skip_scans)
        all_domain_results.extend(domain_results)
    return all_domain_results

def write_csv(output_file, domains):
    """
    Writes CSV with fields: ['Domain','IP','Open Ports','Application'].
    - Always creates/overwrites file
    - Rendering semantics preserved
    """
    rows_written = 0
    try:
        with open(output_file, 'w', newline='\n') as csvfile:
            fieldnames = ['Domain', 'IP', 'Open Ports', 'Application']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            subdomains_by_ip = {}
            for domain in domains:
                ip_key = str(domain['ip'])
                subdomains_by_ip.setdefault(ip_key, []).append(domain)

            for ip_key, subdomain_list in sorted(subdomains_by_ip.items(), key=lambda x: x[0]):
                domains_str = ', '.join(sorted(set(d['subdomain'] for d in subdomain_list if d['subdomain'])))

                all_na = True
                ports_union = set()

                for d in subdomain_list:
                    op = d.get('open_ports')
                    if isinstance(op, str) and op.upper() == 'N/A':
                        continue
                    all_na = False
                    if isinstance(op, set):
                        ports_union.update(op)
                    elif op is None:
                        pass
                    else:
                        try:
                            ports_union.add(int(op))
                        except Exception:
                            pass

                if all_na:
                    open_ports_str = 'N/A'
                else:
                    open_ports_str = ', '.join(sorted(str(p) for p in ports_union)) if ports_union else 'None'

                application = ', '.join(sorted(list(set(
                    a for d in subdomain_list for a in d['application'] if a
                ))))

                writer.writerow({'Domain': domains_str, 'IP': ip_key, 'Open Ports': open_ports_str, 'Application': application})
                rows_written += 1
    except Exception as e:
        print(f"[!] Failed to write CSV to {output_file}: {e}")
        raise
    abs_path = os.path.abspath(output_file)
    print(f"[i] CSV written: {abs_path} ({rows_written} data row(s) + header)")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automated enumeration and reconnaissance tool')
    parser.add_argument('domains', nargs='+', help='The target domains to scan')
    parser.add_argument('-i', '--input', help='A file containing IP addresses and address ranges to scan')
    parser.add_argument('--subs-file', help='Optional file with one subdomain per line to include in enumeration')
    parser.add_argument('--skip-scans', action='store_true', help='Skip Nmap and Nuclei scans')
    parser.add_argument('--subs-include-external', action='store_true',
                    help='Include user-provided subs that do not end with the parent domain for each parent (may duplicate work)')
    args = parser.parse_args()

    output_file = os.path.abspath(f"{args.domains[0]}_output.csv")
    print(f"[i] Output will be written to: {output_file}")

    input_ips = process_input_file(args.input) if args.input else set()
    subs_set = load_subs_file(args.subs_file) if args.subs_file else None

    try:
        domains = scan_domains(args.domains, input_ips, subs_set=subs_set, skip_scans=args.skip_scans)
        write_csv(output_file, domains)
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
        if 'domains' in locals():
            write_csv(output_file, domains)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        if 'domains' in locals():
            try:
                write_csv(output_file, domains)
            except Exception:
                pass
        sys.exit(1)
