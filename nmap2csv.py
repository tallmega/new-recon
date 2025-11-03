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

def build_input_ip_map(inputs: List[str]) -> Tuple[Dict[str, Set[str]], List[Tuple[ipaddress._BaseNetwork, str]]]:
    """
    Given a list of input strings, return:
      - ip_to_inputs: { ip_str -> set(input_strings) } for exact-IP and resolved hostnames
      - cidr_list: list of tuples (network_object, original_input_string) for CIDR inputs
    Note: input list order is preserved when writing CSV (we will join multiple input names with ';').
    """
    ip_to_inputs: Dict[str, Set[str]] = collections.defaultdict(set)
    cidr_list: List[Tuple[ipaddress._BaseNetwork, str]] = []

    for inp in inputs:
        # try exact IP
        try:
            ipobj = ipaddress.ip_address(inp)
            ip_str = str(ipobj)
            ip_to_inputs[ip_str].add(inp)
            continue
        except Exception:
            pass

        # try CIDR/network
        try:
            net = ipaddress.ip_network(inp, strict=False)
            cidr_list.append((net, inp))
            continue
        except Exception:
            pass

        # otherwise treat as hostname/FQDN -> resolve A/AAAA
        resolved = try_resolve_hostname(inp)
        if resolved:
            for rip in resolved:
                ip_to_inputs[rip].add(inp)
        else:
            # If resolution failed, we still want the input listed in output for visibility
            # but without mapping to an IP. We'll handle that later by ensuring it's present in
            # the set of input-only names (so it's not lost).
            # For now, mark a special key "__UNRESOLVED__:"+inp to ensure it's known.
            ip_to_inputs[f"__UNRESOLVED__:{inp}"].add(inp)

    return ip_to_inputs, cidr_list

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
def write_csv(output_path: str, ports_by_ip: Dict[str, Set[str]], names_by_ip: Dict[str, str],
              ip_to_inputs: Dict[str, Set[str]], cidr_list: List[Tuple[ipaddress._BaseNetwork, str]],
              all_inputs_ordered: List[str]) -> int:
    """
    Write CSV: Name,IP,Ports
    Name is derived from (in order of preference):
      1) input strings that map to the IP (exact IP mapping or resolved hostname), joined with ';' in input order
      2) CIDR inputs that contain the IP (joined ';' in input order)
      3) (optional) names_by_ip (reverse lookup) -- we leave blank if none of the above exist, per your request.
    Also include any unresolved input names (from -iL) that had no mapped IPs as rows with empty IP/Ports.
    """
    # Build a map ip -> list of input names in the original input order
    ip_to_input_ordered: Dict[str, List[str]] = {}
    for ip, inputs in ip_to_inputs.items():
        # skip the special unresolved marker here; handle later
        if ip.startswith("__UNRESOLVED__:"):
            continue
        # preserve the order of all_inputs_ordered when emitting joined names
        ordered = [s for s in all_inputs_ordered if s in inputs]
        if ordered:
            ip_to_input_ordered[ip] = ordered
        else:
            # fallback - arbitrary order
            ip_to_input_ordered[ip] = sorted(inputs)

    rows = 0
    # Collect set of IPs to write (merge ports_by_ip keys and any ip_to_input_ordered keys)
    ips_set = set(ports_by_ip.keys()) | set(ip_to_input_ordered.keys())

    with open(output_path, "w", newline="") as csvf:
        w = csv.writer(csvf)
        w.writerow(["Name", "IP", "Ports"])

        # First, emit rows for scanned IPs (sorted numerically)
        for ip in sort_ips_numerically(list(ips_set)):
            # Determine input name(s)
            names_for_ip: List[str] = []
            if ip in ip_to_input_ordered:
                names_for_ip.extend(ip_to_input_ordered[ip])
            # If no exact/resolved mapping, check CIDRs
            if not names_for_ip:
                cidr_matches = ips_in_cidr_mappings(ip, cidr_list)
                # preserve original input order for CIDR matches
                names_for_ip.extend([s for s in all_inputs_ordered if s in cidr_matches])
            # If still none, we intentionally do NOT use reverse PTR as primary; keep blank
            name_cell = ";".join(names_for_ip)

            ports_list = sorted(ports_by_ip.get(ip, set()), key=lambda p: int(p)) if ports_by_ip.get(ip) else []
            if ports_list:
                ports_cell = ",".join(f"tcp/{p}" for p in ports_list)
            else:
                ports_cell = "None"
            w.writerow([name_cell, ip, ports_cell])
            rows += 1

        # Then, emit any unresolved input names that had no mapped IPs (so you see them in output)
        for key in sorted(ip_to_inputs.keys()):
            if not key.startswith("__UNRESOLVED__:"):
                continue
            orig = key.split(":", 1)[1]
            # ensure we don't duplicate an existing row for this input (e.g., input was resolved)
            # check whether orig appears in any name_cell already; if not, emit a row
            found = False
            # cheap check: if orig was included in any ip_to_input_ordered values or cidr_list, skip
            for inputs in ip_to_input_ordered.values():
                if orig in inputs:
                    found = True
                    break
            if not found:
                # not resolved and not represented; emit a row with empty IP/Ports so you can see it
                w.writerow([orig, "", ""])
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
    ip_to_inputs_map, cidr_list = build_input_ip_map(all_inputs)

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
    rows_written = write_csv(args.output, ports_by_ip, names_by_ip, ip_to_inputs_map, cidr_list, all_inputs)
    print(f"Wrote {rows_written} rows to {args.output}", file=sys.stderr)

if __name__ == "__main__":
    main()
