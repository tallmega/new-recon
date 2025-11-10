#!/usr/bin/env python3
"""
nmap_to_csv.py

Run nmap (grepable output) against targets and produce CSV: Name,IP,Ports

Leftmost column is the original input (FQDN / IP / CIDR) you provided so you always
know what you asked nmap to scan.

Usage examples:
  python nmap_to_csv.py host1.example.com host2.example.com
  python nmap_to_csv.py -iL targets.txt -o results.csv
  python nmap_to_csv.py -iL targets.txt 10.0.0.0/24 --top-ports 200 -o results.csv

Important: Only scan networks you are authorized to scan.
"""
from __future__ import annotations
import argparse
import collections
import csv
import ipaddress
import re
import shlex
import socket
import subprocess
import sys
from typing import Dict, List, Set, Tuple

# --- Regexes ---------------------------------------------------------------
PORTS_RE = re.compile(r'Ports:\s*(.+)')
OPEN_PORT_RE = re.compile(r'(\d+)\/open')
HOST_LINE_RE = re.compile(r'^Host:\s+(\S+)\s+\((.*?)\)')

# --- Build / run nmap -----------------------------------------------------
def build_nmap_command(
    targets: list[str],
    *,
    input_file: str | None = None,
    ports: str | None = None,
    top_ports: int | None = None,
    include_empty: bool = False,
    extra_args: list[str] = [],
) -> list[str]:
    cmd = ["nmap", "-Pn", "-T4", "-oG", "-"]
    if not include_empty:
        cmd += ["--open"]
    if top_ports:
        cmd += ["--top-ports", str(top_ports)]
    elif ports:
        cmd += ["-p", ports]
    if extra_args:
        cmd += extra_args
    if input_file:
        cmd += ["-iL", input_file]
    if targets:
        cmd += targets
    return cmd

def run_nmap_and_capture(cmd: List[str]) -> str:
    print("Running:", " ".join(shlex.quote(x) for x in cmd), file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        print("nmap failed:", proc.stderr.strip(), file=sys.stderr)
        proc.check_returncode()
    return proc.stdout

# --- Parsers ---------------------------------------------------------------
def parse_grepable_to_dict_with_names(nmap_output: str) -> Tuple[Dict[str, Set[str]], Dict[str, str]]:
    """
    Parse nmap -oG output and return:
      - ports_by_ip: { ip -> set of port strings }
      - names_by_ip: { ip -> reverse-lookup hostname (may be empty) } (kept but not prioritized)
    """
    ports_by_ip: Dict[str, Set[str]] = collections.defaultdict(set)
    names_by_ip: Dict[str, str] = {}

    for raw in nmap_output.splitlines():
        line = raw.strip()
        if not line or not line.startswith("Host:"):
            continue

        ip = None
        hostname = ""
        m_host = HOST_LINE_RE.search(line)
        if m_host:
            ip = m_host.group(1)
            hostname = m_host.group(2) or ""
        else:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1]

        if not ip:
            continue

        # record PTR name if present (we won't prefer it over input name)
        if hostname:
            names_by_ip[ip] = hostname
        elif ip not in names_by_ip:
            names_by_ip[ip] = ""

        # collect ports if the line includes a Ports: field
        m_ports = PORTS_RE.search(line)
        if m_ports:
            ports_field = m_ports.group(1)
            for pm in OPEN_PORT_RE.finditer(ports_field):
                ports_by_ip[ip].add(pm.group(1))

    return ports_by_ip, names_by_ip

# --- Input resolution / mapping -------------------------------------------
def read_input_list(positional: List[str], input_file: str | None) -> List[str]:
    """Return ordered list of inputs gathered from -iL file (if provided) then positional targets."""
    inputs: List[str] = []
    if input_file:
        with open(input_file, "r") as fh:
            for line in fh:
                t = line.strip()
                if not t or t.startswith("#"):
                    continue
                inputs.append(t)
    # Append positional targets after file entries (preserve order)
    if positional:
        inputs.extend([t for t in positional if t and not t.startswith("#")])
    return inputs

def try_resolve_hostname(name: str) -> Set[str]:
    """Resolve a hostname to A/AAAA addresses using socket.getaddrinfo."""
    ips: Set[str] = set()
    try:
        for res in socket.getaddrinfo(name, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM):
            # res[4][0] is the IP
            ip = res[4][0]
            ips.add(ip)
    except Exception:
        # resolution failed; return empty set
        pass
    return ips

def build_input_ip_map(inputs: List[str]) -> Tuple[
    Dict[str, Set[str]],                       # ip_to_inputs
    List[Tuple[ipaddress._BaseNetwork, str]],  # cidr_list
    Dict[str, Set[str]],                       # name_to_ips
    Set[str],                                  # unresolved_names
]:
    """
    Given a list of input strings, return:
      - ip_to_inputs: { ip_str -> set(input_strings) } for exact-IP and resolved hostnames
      - cidr_list:    list of (network_object, original_input_string) for CIDR inputs
      - name_to_ips:  { input_name (usually FQDN) -> set(ip_str) } for hostnames we resolved (and IP literals)
      - unresolved_names: set of input names that didn't resolve to any IP
    """
    ip_to_inputs: Dict[str, Set[str]] = collections.defaultdict(set)
    cidr_list: List[Tuple[ipaddress._BaseNetwork, str]] = []
    name_to_ips: Dict[str, Set[str]] = collections.defaultdict(set)
    unresolved_names: Set[str] = set()

    for inp in inputs:
        # exact IP?
        try:
            ipobj = ipaddress.ip_address(inp)
            ip_str = str(ipobj)
            ip_to_inputs[ip_str].add(inp)
            name_to_ips[inp].add(ip_str)  # treat an IP input as "name" mapping to itself
            continue
        except Exception:
            pass

        # CIDR?
        try:
            net = ipaddress.ip_network(inp, strict=False)
            cidr_list.append((net, inp))
            continue
        except Exception:
            pass

        # assume hostname/FQDN
        resolved = try_resolve_hostname(inp)
        if resolved:
            for rip in resolved:
                ip_to_inputs[rip].add(inp)
                name_to_ips[inp].add(rip)
        else:
            unresolved_names.add(inp)

    return ip_to_inputs, cidr_list, name_to_ips, unresolved_names


# --- Helpers ---------------------------------------------------------------
def include_up_hosts_without_ports(nmap_output_all: str, ports_by_ip: Dict[str, Set[str]]) -> None:
    for line in nmap_output_all.splitlines():
        line = line.strip()
        if not line or not line.startswith("Host:"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        if "Status: Up" in line and ip not in ports_by_ip:
            ports_by_ip[ip] = set()

def sort_ips_numerically(ips: List[str]) -> List[str]:
    def key_func(addr: str):
        try:
            return int(ipaddress.ip_address(addr))
        except Exception:
            return addr
    return sorted(ips, key=key_func)

def ips_in_cidr_mappings(ip: str, cidr_list: List[Tuple[ipaddress._BaseNetwork, str]]) -> List[str]:
    """Return list of input strings (CIDR original) whose network contains ip."""
    ipobj = ipaddress.ip_address(ip)
    matches: List[str] = []
    for net, orig in cidr_list:
        try:
            if ipobj in net:
                matches.append(orig)
        except Exception:
            continue
    return matches

# --- CSV writer ------------------------------------------------------------
def write_csv(output_path: str,
              ports_by_ip: Dict[str, Set[str]],
              names_by_ip: Dict[str, str],   # unused for precedence, kept for compatibility
              ip_to_inputs: Dict[str, Set[str]],
              cidr_list: List[Tuple[ipaddress._BaseNetwork, str]],
              all_inputs_ordered: List[str],
              name_to_ips: Dict[str, Set[str]],
              unresolved_names: Set[str]) -> int:
    """
    CSV columns: Name,IP,Ports

    - For each input FQDN (or single-IP "name"), collapse to ONE ROW:
        * If any of its resolved IPs have open ports:
              IP  = the open-IPs joined by ';'
              Ports = union of open ports across those IPs (tcp/ prefix)
        * Else:
              IP  = all resolved IPs joined by ';' (or blank if none)
              Ports = "None"
    - For CIDR inputs (or any remaining scanned IPs not shown via a hostname row):
        emit per-IP rows with that CIDR as Name.
    - Unresolved input names (that never resolved and weren’t represented) get a row:
        Name = input, IP = "", Ports = "None"
    """
    rows = 0
    emitted_ips: Set[str] = set()

    def join_ips(ips: List[str]) -> str:
        return ";".join(sort_ips_numerically(list(ips))) if ips else ""

    with open(output_path, "w", newline="") as csvf:
        w = csv.writer(csvf)
        w.writerow(["Name", "IP", "Ports"])

        # 1) Emit one row per input "name" that has a mapping (FQDN or an IP literal treated as a name)
        for name in all_inputs_ordered:
            if name not in name_to_ips:
                continue  # likely a CIDR or unresolved
            resolved_ips = list(name_to_ips.get(name, set()))
            if not resolved_ips:
                # no resolved IPs; we'll show under unresolved later if needed
                continue

            # Split into IPs with open ports vs without
            open_ip_list = [ip for ip in resolved_ips if ports_by_ip.get(ip)]
            if open_ip_list:
                # Collapse to single row: IPs = the ones with open ports; Ports = union of their ports
                union_ports: Set[str] = set()
                for ip in open_ip_list:
                    union_ports.update(ports_by_ip[ip])
                ports_cell = ",".join(f"tcp/{p}" for p in sorted(union_ports, key=lambda p: int(p)))
                ip_cell = join_ips(open_ip_list)
                w.writerow([name, ip_cell, ports_cell])
                rows += 1
                emitted_ips.update(open_ip_list)
            else:
                # None of the resolved IPs have open ports
                ip_cell = join_ips(resolved_ips)
                w.writerow([name, ip_cell, "None"])
                rows += 1
                # don't mark emitted_ips, these had no open ports

        # 2) Emit per-IP rows for any remaining scanned IPs (e.g., from CIDRs)
        #    Associate to the first matching CIDR (or join all matches if you prefer).
        def cidr_name_for_ip(ip: str) -> str:
            matches = [label for net, label in cidr_list if ipaddress.ip_address(ip) in net]
            return matches[0] if matches else ""  # pick first match

        for ip in sort_ips_numerically([ip for ip in ports_by_ip.keys() if ip not in emitted_ips]):
            # skip if this IP was covered in a hostname row above
            covered = False
            for name, ips in name_to_ips.items():
                if ip in ips:
                    covered = True
                    break
            if covered:
                continue

            ports_list = sorted(ports_by_ip.get(ip, set()), key=lambda p: int(p))
            if not ports_list:
                # no open ports -> only show if you want to list every scanned IP; spec says we don't need to
                continue

            name_cell = cidr_name_for_ip(ip)
            ports_cell = ",".join(f"tcp/{p}" for p in ports_list)
            w.writerow([name_cell, ip, ports_cell])
            rows += 1

        # 3) Emit unresolved input names (never resolved and not represented above)
        for name in all_inputs_ordered:
            if name in name_to_ips:
                continue  # already emitted above
            if name in unresolved_names:
                w.writerow([name, "", "None"])
                rows += 1

    return rows


# --- CLI -------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run nmap and output CSV: Name,IP,Ports")
    ap.add_argument("targets", nargs="*", help="Target ranges/hosts (CIDR, IP, hostname).")
    ap.add_argument("-iL", "--input-file", help="File with one target per line (passed to nmap as -iL).")
    ap.add_argument("-o", "--output", default="nmap_results.csv", help="CSV output file")
    ap.add_argument("--ports", default="1-1024", help="nmap -p argument (default 1-1024)")
    ap.add_argument("--top-ports", type=int, help="Use nmap --top-ports N instead of -p")
    ap.add_argument("--extra", nargs="*", default=[], help="Extra nmap args (e.g. -sV -sC)")
    ap.add_argument("--include-empty", action="store_true",
                    help="Include 'Up' hosts with no open ports (disables --open)")
    return ap.parse_args()

def main() -> None:
    args = parse_args()

    # Read ordered inputs (file then positional)
    all_inputs = read_input_list(args.targets, args.input_file)
    if not all_inputs:
        print("Provide targets (positional) or -iL/--input-file.", file=sys.stderr)
        sys.exit(2)

    # Build mapping from input -> resolved IPs / CIDRs
    ip_to_inputs_map, cidr_list, name_to_ips, unresolved_names = build_input_ip_map(all_inputs)

    # Build and run nmap
    cmd = build_nmap_command(
        args.targets,
        input_file=args.input_file,
        ports=None if args.top_ports else args.ports,
        top_ports=args.top_ports,
        include_empty=args.include_empty,
        extra_args=args.extra,
    )
    nmap_stdout = run_nmap_and_capture(cmd)

    # Parse nmap output (ports + reverse names)
    ports_by_ip, names_by_ip = parse_grepable_to_dict_with_names(nmap_stdout)

    if args.include_empty:
        include_up_hosts_without_ports(nmap_stdout, ports_by_ip)

    # Write CSV: preferences: input mapping (exact/resolved) -> CIDR contains -> blank (no reverse PTR)
    rows_written = write_csv(
    args.output,
    ports_by_ip,
    names_by_ip,
    ip_to_inputs_map,
    cidr_list,
    all_inputs,
    name_to_ips,
    unresolved_names,
    )
    print(f"Wrote {rows_written} rows to {args.output}", file=sys.stderr)

if __name__ == "__main__":
    main()
