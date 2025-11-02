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

def resolve_subdomains(subdomains, target_domain):
    resolved_subdomains = defaultdict(set)
    for subdomain in subdomains:
        try:
            ip_addresses = set(socket.gethostbyname_ex(subdomain.rstrip('.'))[2])
            for ip in ip_addresses:
                resolved_subdomains[ip].add(subdomain)
        except (socket.gaierror, ValueError):
            # keep behaviour of notifying the user
            print(f"Error resolving subdomain {subdomain}: host not found")
    return resolved_subdomains

def process_input_ips(input_ips, resolved_subdomains):
    """
    Build domain entries for IPs that came from the input file.
    - If an input IP is present in resolved_subdomains, we attach the subdomains and mark open_ports as set() (not scanned yet).
    - If input IP has no matching subdomain, mark open_ports as 'N/A' (not scanned).
    """
    domains = []
    for ip in sorted(input_ips):
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            # keep any non-IP (shouldn't happen here) as-is
            ip_str = ip
            # treat as not-scanned
            domains.append({
                'ip': ip_str,
                'subdomain': '',
                'open_ports': 'N/A',
                'application': []
            })
            continue

        if str(ip_obj) in resolved_subdomains:
            domains.append({
                'ip': ip_obj,
                'subdomain': ', '.join(sorted(resolved_subdomains[str(ip_obj)])),
                'open_ports': set(),   # scanned (conceptually) but no scan performed yet — will be interpreted as "scanned but no ports" unless updated
                'application': []
            })
        else:
            domains.append({
                'ip': ip_obj,
                'subdomain': '',
                'open_ports': 'N/A',   # explicitly not scanned
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
                ['nmap', '-Pn', '-p', '1-65535', '--host-timeout', '45m', str(ip)],
                stdout=subprocess.PIPE, stderr=devnull, encoding='utf-8', check=False
            )
        except FileNotFoundError:
            print("nmap not found in PATH. Skipping scan for", ip)
            return 'N/A'

        lines = result.stdout.splitlines()
        for line in lines:
            # nmap's output has many lines; check for "open" state, but avoid "filtered" or other words
            # We'll do a conservative parse: lines that start with digits followed by '/' and 'open' somewhere
            parts = line.strip().split()
            if not parts:
                continue
            # naive pattern: "<port>/<proto>  open  service"
            m = re.match(r'^(\d+)\/', parts[0])
            if m and 'open' in line:
                try:
                    port = int(m.group(1))
                    open_ports.add(port)
                except Exception:
                    pass
    return open_ports  # possibly empty set

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

def resolve_subdomains_with_cname_handling(subdomains, target_domain):
    """
    More complete resolve_subdomains which handles CNAMEs that point outside the target domain.
    Returns mapping: key -> set(subdomains)
    where key is either IP (string) or external CNAME target (string)
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
                # dns.resolver returns rdata; format as string
                cname_records.add(str(cname.target).rstrip('.'))

            for cname in cname_records:
                # If the CNAME target doesn't end with the target domain, treat it as "external"
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
                # keep the original behaviour of printing errors
                print(f"Error resolving subdomain {subdomain}: host not found")
    return resolved_subdomains

def scan_domain(domain, input_ips, skip_scans=False):
    """
    Scans one parent domain:
      - runs subfinder
      - runs gobuster depending on wildcard
      - resolves subdomains (IP or external CNAME targets)
      - scans IPs (unless skip_scans)
      - gathers CNAMES as not-scanned entries
      - returns list of domain_info dicts
    """
    print(f'Enumerating subdomains for \'{domain}\' with subfinder...')
    try:
        with open(os.devnull, 'w') as devnull:
            subfinder_out = subprocess.check_output(['subfinder', '-d', domain, '-silent'], stderr=devnull, encoding='utf-8')
            subdomains = set(subfinder_out.split())
    except FileNotFoundError:
        print("subfinder not found in PATH. No subdomain enumeration performed.")
        subdomains = set()
    except subprocess.CalledProcessError:
        subdomains = set()

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
            # if gobuster or wordlist missing, continue with subfinder results
            pass
    else:
        # run gobuster to get more subdomains
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
                subdomains |= gobuster_subdomains
        except Exception:
            # gobuster missing or failing - keep subfinder results
            pass

    subdomains = sorted(set(subdomains))
    resolved_subdomains = resolve_subdomains_with_cname_handling(subdomains, domain)

    # Separate cnames vs IPs for later inclusion
    cnames = {}
    ips_map = {}
    for k, v in resolved_subdomains.items():
        try:
            ip_obj = ipaddress.ip_address(k)
            # keep only global IPs (mirrors your previous logic)
            if ip_obj.is_global:
                ips_map[str(k)] = v
        except ValueError:
            # k isn't an IP — treat as a CNAME (external)
            cnames[k] = v

    # Build the set of keys to iterate: include resolved keys (IPs + cnames) plus any user-provided input IPs
    keys_to_scan = set(resolved_subdomains.keys()) | set(input_ips)

    print('Running port scan on IPs...')
    domains = []

    # For each key, attempt to treat it as an IP. If it's not an IP (i.e. CNAME), we'll skip scanning it here.
    for key in sorted(keys_to_scan):
        # skip empty
        if not key:
            continue

        try:
            ip_obj = ipaddress.ip_address(key)
        except ValueError:
            # key is not an IP (likely a CNAME). We'll add it later when adding cnames.
            continue

        open_ports = scan_ports(ip_obj, skip_scans)

        # If there are subdomains mapped to this IP, create one row *per subdomain* (keeps previous behaviour)
        mapped_subs = resolved_subdomains.get(str(ip_obj), [])
        if mapped_subs:
            for subdomain in sorted(mapped_subs):
                if isinstance(open_ports, str) and open_ports == 'N/A':
                    # not-scanned entry
                    domain_info = {
                        'ip': ip_obj,
                        'subdomain': subdomain,
                        'open_ports': 'N/A',
                        'application': []
                    }
                else:
                    # scanned (open_ports is a set, possibly empty)
                    domain_info = {
                        'ip': ip_obj,
                        'subdomain': subdomain,
                        'open_ports': open_ports if isinstance(open_ports, set) else set(),
                        'application': []
                    }
                domains.append(domain_info)
        else:
            # No mapped subdomains for this IP. If input provided this IP, we want the input row (N/A or scanned)
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
                # This IP came from DNS resolution but had no subdomain (unlikely); skip unless scanned and has ports.
                if isinstance(open_ports, set) and open_ports:
                    domains.append({
                        'ip': ip_obj,
                        'subdomain': '',
                        'open_ports': open_ports,
                        'application': []
                    })
                # otherwise skip (we don't include scanned-but-empty IPs without a subdomain unless they were in input_ips)

    # Add process_input_ips results ONCE (so input-only IPs get their 'N/A' entries if not present)
    domains.extend(process_input_ips(input_ips, resolved_subdomains))

    # Add CNAMES (external targets) as rows (not scanned)
    for cname_key, subdomains_set in cnames.items():
        domains.append({
            'ip': cname_key,
            'subdomain': ', '.join(sorted(subdomains_set)),
            'open_ports': 'N/A',
            'application': []
        })

    # Nuclei scanning (only when not skipped)
    if not skip_scans:
        print('Running nuclei scans...')
        for d in domains:
            op = d.get('open_ports')
            # we only nuclei-scan if op is a set with ints
            if isinstance(op, (set, list, tuple)) and op:
                for port in sorted(op):
                    if isinstance(port, int):
                        application = run_nuclei(domain=d['subdomain'] or str(d['ip']), port=port)
                        if application:
                            d['application'].append(application)

    return domains

def scan_domains(domains_list, input_ips, skip_scans=False):
    all_domain_results = []
    for domain in domains_list:
        domain_results = scan_domain(domain, input_ips, skip_scans)
        all_domain_results.extend(domain_results)
    return all_domain_results

def write_csv(output_file, domains):
    """
    Writes CSV with fields: ['Domain','IP','Open Ports','Application'].
    - Always creates/overwrites the file, even if domains is empty (header only).
    - Same rendering semantics you expect for 'Open Ports' handled upstream.
    """
    rows_written = 0
    try:
        with open(output_file, 'w', newline='\n') as csvfile:
            fieldnames = ['Domain', 'IP', 'Open Ports', 'Application']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # group subdomains by IP address or CNAME record (stringify ip for consistent keys)
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
                        # scanned but no ports; leave union empty
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
    parser.add_argument('--skip-scans', action='store_true', help='Skip Nmap and Nuclei scans')
    args = parser.parse_args()

    # Build output path up-front and show it
    output_file = os.path.abspath(f"new-recon-{args.domains[0]}_output.csv")
    print(f"[i] Output will be written to: {output_file}")

    try:
        input_ips = process_input_file(args.input) if args.input else set()
        domains = scan_domains(args.domains, input_ips, args.skip_scans)

        # Safety: domains might be empty; we still write header so there is a file
        write_csv(output_file, domains)
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
        # still try to write anything we collected so far if variable exists
        try:
            if 'domains' in locals():
                write_csv(output_file, domains)
        except Exception:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        # If you want a traceback for debugging uncomment:
        # import traceback; traceback.print_exc()
        # Still write whatever we have, if available
        try:
            if 'domains' in locals():
                write_csv(output_file, domains)
        except Exception:
            pass
        sys.exit(1)