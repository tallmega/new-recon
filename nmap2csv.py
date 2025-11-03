#!/usr/bin/env python3
"""
nmap_to_csv.py

Run nmap (grepable output) against targets and produce CSV: IP,Ports

Usage examples:
  python nmap_to_csv.py 10.0.0.0/24
  python nmap_to_csv.py -iL targets.txt -o results.csv
  python nmap_to_csv.py --top-ports 100 10.0.0.0/24 -o top100.csv
  python nmap_to_csv.py --ports 1-65535 10.0.0.0/24 -o allports.csv
  python nmap_to_csv.py --include-empty 10.0.0.0/24   # include hosts with no open ports (remove --open behavior)

Important: Only scan networks you are authorized to scan.
"""
from __future__ import annotations
import argparse
import collections
import csv
import ipaddress
import re
import shlex
import subprocess
import sys
from typing import Dict, List, Set, Tuple

PORTS_RE = re.compile(r'Ports:\s*(.+)')
OPEN_PORT_RE = re.compile(r'(\d+)\/open')

def build_nmap_command(targets: List[str], ports: str | None = None, top_ports: int | None = None,
                       include_empty: bool = False, extra_args: List[str] = []) -> List[str]:
    """
    Construct the nmap command list.
    - If top_ports is provided, uses --top-ports N
    - If include_empty is False (default), adds --open to only return hosts with open ports.
    """
    cmd = ["nmap", "-Pn", "-T4", "-oG", "-"]
    if not include_empty:
        cmd += ["--open"]
    if top_ports:
        cmd += ["--top-ports", str(top_ports)]
    elif ports:
        cmd += ["-p", ports]
    if extra_args:
        # allow user to pass flags like '-sV' or '--script=http-title'
        cmd += extra_args
    cmd += targets
    return cmd

def run_nmap_and_capture(cmd: List[str]) -> str:
    """Run nmap and return stdout (grepable output). Allow return code 1 as nmap sometimes returns 1 for host down."""
    print("Running:", " ".join(shlex.quote(x) for x in cmd), file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        # Non-recoverable error
        print("nmap failed:", proc.stderr.strip(), file=sys.stderr)
        proc.check_returncode()
    return proc.stdout

def parse_grepable_to_dict(nmap_output: str) -> Dict[str, Set[str]]:
    """
    Parse nmap -oG output and return dictionary { ip -> set(port strings) }.
    Only lines with a 'Ports:' field are considered (avoids empty duplicate rows).
    Ports are collected across multiple lines for the same IP (merged).
    """
    ports_by_ip: Dict[str, Set[str]] = collections.defaultdict(set)

    for line in nmap_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("Host:"):
            continue

        m_ports = PORTS_RE.search(line)
        if not m_ports:
            # skip Host lines that do not include a Ports: field (these are often Status: Up, etc.)
            continue

        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[1]

        ports_field = m_ports.group(1)
        for pm in OPEN_PORT_RE.finditer(ports_field):
            ports_by_ip[ip].add(pm.group(1))

    return ports_by_ip

def include_up_hosts_without_ports(nmap_output_all: str, ports_by_ip: Dict[str, Set[str]]) -> None:
    """
    If user wants to include hosts that are up but have no open ports,
    parse Status: Up host lines and ensure they exist in the dict with empty set.
    """
    for line in nmap_output_all.splitlines():
        line = line.strip()
        if not line or not line.startswith("Host:"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        # detect 'Status: Up' in line text
        if "Status: Up" in line and ip not in ports_by_ip:
            ports_by_ip[ip] = set()

def sort_ips_numerically(ips: List[str]) -> List[str]:
    """Return IPs sorted numerically where possible (IPv4/IPv6)."""
    def key_func(addr: str):
        try:
            return int(ipaddress.ip_address(addr))
        except Exception:
            return addr
    return sorted(ips, key=key_func)

def write_csv(output_path: str, ports_by_ip: Dict[str, Set[str]]) -> int:
    """Write CSV with header IP,Ports (ports comma-separated). Returns number of rows written."""
    rows = 0
    with open(output_path, "w", newline="") as csvf:
        w = csv.writer(csvf)
        w.writerow(["IP", "Ports"])
        for ip in sort_ips_numerically(list(ports_by_ip.keys())):
            ports_list = sorted(ports_by_ip[ip], key=lambda p: int(p)) if ports_by_ip[ip] else []
            w.writerow([ip, ",".join(ports_list)])
            rows += 1
    return rows

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run nmap and output CSV: IP,Ports")
    ap.add_argument("targets", nargs="*", help="Target ranges / hosts. Use -iL to provide a file instead.")
    ap.add_argument("-iL", "--input-file", help="File with one target per line (CIDR, host, range).")
    ap.add_argument("-o", "--output", default="nmap_results.csv", help="CSV output file (default nmap_results.csv)")
    ap.add_argument("--ports", default="1-1024",
                    help="nmap -p argument (default 1-1024). Use '1-65535' for all ports (much slower).")
    ap.add_argument("--top-ports", type=int,
                    help="Alternative: scan top N most common ports via nmap --top-ports N (overrides --ports).")
    ap.add_argument("--extra", nargs="*", default=[], help="Extra nmap arguments (e.g. -sV -sC). Do not quote multiple flags.")
    ap.add_argument("--include-empty", action="store_true",
                    help="Include hosts 'Up' with no open ports as rows with empty Ports (disables automatic --open filter).")
    return ap.parse_args()

def main() -> None:
    args = parse_args()

    targets: List[str] = []
    if args.input_file:
        with open(args.input_file, "r") as f:
            for line in f:
                t = line.strip()
                if t and not t.startswith("#"):
                    targets.append(t)
    if args.targets:
        targets.extend(args.targets)

    if not targets:
        print("No targets provided (positional targets or -iL file).", file=sys.stderr)
        sys.exit(2)

    # Build nmap command
    extra_args = args.extra or []
    ports_arg = None if args.top_ports else args.ports
    cmd = build_nmap_command(targets, ports=ports_arg, top_ports=args.top_ports,
                             include_empty=args.include_empty, extra_args=extra_args)

    nmap_stdout = run_nmap_and_capture(cmd)

    # Parse ports from grepable output (only lines with Ports: are considered)
    ports_by_ip = parse_grepable_to_dict(nmap_stdout)

    # If include_empty requested, ensure 'Up' hosts without Ports are included
    if args.include_empty:
        # To find up hosts we need the full output: the grepable output already contains Status: Up lines,
        # so use the same captured output to detect them.
        include_up_hosts_without_ports(nmap_stdout, ports_by_ip)

    rows_written = write_csv(args.output, ports_by_ip)
    print(f"Wrote {rows_written} rows to {args.output}", file=sys.stderr)

if __name__ == "__main__":
    main()
