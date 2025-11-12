#!/usr/bin/env python3
"""Summarize new-recon output CSVs or screenshot HTML reports and call OpenAI for narrative insights."""

from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    from bs4 import BeautifulSoup  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    BeautifulSoup = None  # type: ignore

try:
    import tldextract  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    tldextract = None  # type: ignore

HOST_RE = re.compile(r"\b(?:(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+)\b")
HOSTNAME_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9\-.]{1,252}$")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

HTML_STYLE_BLOCK = (
    "body{font-family:Arial,Helvetica,sans-serif;margin:20px;}"
    "table{border-collapse:collapse;width:100%;border:1px solid #000;background:#fff;table-layout:fixed;}"
    "th,td{border:1px solid #000;padding:8px 10px;vertical-align:top;font-size:9pt;}"
    "th{background:#000;color:#ffd400;font-weight:bold;}"
    "tbody tr:nth-child(odd) td{background:#f7f7f7;}"
    "tbody tr:nth-child(even) td{background:#ededed;}"
    "td img{width:2in !important;max-width:none !important;max-height:none !important;border:1px solid #888;margin:6px auto;display:block;}"
    ".shot-block{margin:0 auto 12px auto;text-align:center;border:1px solid #ccc;padding:6px;background:#fff;}"
    ".shot-label{font-weight:bold;font-size:8pt;margin-bottom:4px;word-break:break-all;}"
    ".shot-pending{font-style:italic;color:#666;}"
    ".shot-error{color:#a00;font-weight:bold;margin:4px 0;}"
    ".col-ip{width:20%;}"
    ".col-port{width:10%;}"
    ".note-text{margin-bottom:10px;font-style:italic;text-align:left;}"
    ".note-entry{margin-bottom:12px;}"
    ".report-section{margin-bottom:40px;}"
    ".report-section h2{border-bottom:2px solid #000;padding-bottom:4px;margin-bottom:12px;}"
    ".stats-list{list-style-type:disc;margin-left:20px;}"
)


def derive_output_html_path(sample_input: str, provided: Optional[str]) -> str:
    if provided:
        return provided
    path = Path(sample_input)
    name = path.name
    if name.endswith("_output.csv"):
        return str(path.with_name(name.replace("_output.csv", "_output.html")))
    return str(path.with_suffix(path.suffix + ".html"))


def _ensure_html_shell(path: str) -> None:
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            f"<style>{HTML_STYLE_BLOCK}</style>\n"
            "</head>\n<body>\n</body>\n</html>\n"
        )


def append_html_section(path: str, title: str, inner_html: str) -> None:
    _ensure_html_shell(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    section = (
        f"<section class=\"report-section\">\n<h2>{html.escape(title)}</h2>\n"
        f"{inner_html}\n" "</section>\n"
    )
    marker = "</body>"
    if marker in content:
        new_content = content.replace(marker, section + marker, 1)
    else:
        new_content = content + section
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_content)


def _lower_list(values: Sequence[str]) -> List[str]:
    return [v.lower() for v in values]


def _prep_signature_list(signatures: List[Dict[str, object]]) -> None:
    for entry in signatures:
        for key in ("keywords", "url_keywords", "host_suffixes"):
            if key in entry and entry[key]:
                entry[key] = _lower_list(entry[key])  # type: ignore
        if "ports" in entry and entry["ports"]:
            entry["ports"] = {(proto.lower(), int(port)) for proto, port in entry["ports"]}  # type: ignore
        if "patterns" in entry and entry["patterns"]:
            entry["patterns"] = [re.compile(pattern, re.IGNORECASE) for pattern in entry["patterns"]]  # type: ignore

PRIORITY_SOFTWARE = [
    "WordPress",
    "SharePoint",
    "Microsoft Exchange / OWA",
    "Fortinet FortiGate VPN",
    "Palo Alto GlobalProtect",
    "Cisco AnyConnect / ASA",
    "Citrix Gateway / NetScaler",
    "Craft CMS",
    "Magnolia CMS",
    "BeyondTrust Remote Assist",
    "OpenCart",
    "Telus Business Connect",
    "VPN Internet Key Exchange (IKE)",
    "RDP",
]


SOFTWARE_SIGNATURES: List[Dict[str, object]] = [
    {"label": "WordPress", "keywords": ["wordpress", "wp-login", "wp-admin", "wp-content"]},
    {"label": "Microsoft Exchange / OWA", "keywords": ["microsoft exchange", "outlook web app", "owa"]},
    {"label": "Fortinet FortiGate VPN", "keywords": ["fortinet", "fortigate", "forticlient", "acme access only"]},
    {"label": "Palo Alto GlobalProtect", "keywords": ["globalprotect"]},
    {"label": "Cisco AnyConnect / ASA", "keywords": ["anyconnect", "cisco asa"]},
    {"label": "Citrix Gateway / NetScaler", "keywords": ["citrix gateway", "netscaler", "citrix adc"]},
    {"label": "OpenCart", "keywords": ["opencart"]},
    {"label": "Telus Business Connect", "keywords": ["telus business connect"]},
    {"label": "Jenkins", "keywords": ["jenkins", "hudson"]},
    {"label": "Grafana", "keywords": ["grafana"]},
    {"label": "Kibana", "keywords": ["kibana"]},
    {"label": "ElasticSearch", "keywords": ["elasticsearch"]},
    {"label": "SharePoint", "keywords": ["sharepoint"]},
    {"label": "Apache HTTP Server", "keywords": ["apache http server", "apache/"]},
    {"label": "Nginx", "keywords": ["nginx"]},
    {"label": "Microsoft IIS", "keywords": ["microsoft-iis", "internet information services", "iis"]},
    {"label": "Microsoft HTTPAPI", "keywords": ["microsoft-httpapi"]},
    {"label": "ASP.NET", "keywords": ["asp.net", "__viewstate"]},
    {"label": "PHP", "keywords": ["php/", "x-powered-by: php", "phpmyadmin", "php version"], "patterns": [r"\bphp\b"]},
    {"label": "Jetty", "keywords": ["jetty"]},
    {"label": "Django", "keywords": ["django"]},
    {"label": "Ruby on Rails", "keywords": ["ruby on rails", "rails"]},
    {"label": "Craft CMS", "keywords": ["craft cms", "craftcms", "craft-cms"]},
    {"label": "Magnolia CMS", "keywords": ["magnolia cms"]},
    {"label": "Wix", "keywords": ["wix.com", "wixstatic"]},
    {"label": "Cisco Device", "keywords": ["cisco ", "cisco systems", "cisco secure desktop"]},
    {"label": "Proofpoint", "keywords": ["proofpoint"]},
    {"label": "IBM HTTP Server / WebSphere", "keywords": ["ibm http server", "ibm_http_server", "websphere"]},
    {"label": "F5 BIG-IP", "keywords": ["big-ip", "f5 networks"]},
    {"label": "Linksys", "keywords": ["linksys"]},
    {"label": "BeyondTrust Remote Assist", "keywords": ["beyondtrust remoteassist", "beyondtrust remote support", "beyondtrust-remotesupport"]},
    {"label": "Morley Insurance Exchange", "keywords": ["morley insurance exchange"]},
    {"label": "VPN Internet Key Exchange (IKE)", "keywords": ["ike", "ipsec", "internet key exchange", "isakmp"],
     "ports": {("udp", 500), ("udp", 4500)}},
    {"label": "RDP", "ports": {("tcp", 3389)}},
    {"label": "SonicWall VPN", "keywords": ["sonicwall"]},
    {"label": "Fortinet SSL VPN Portal", "keywords": ["fortisslvpn", "fortinet ssl vpn"]},
    {"label": "vSphere / ESXi", "keywords": ["vmware vsphere", "esxi"]},
]

THIRD_PARTY_SIGNATURES: List[Dict[str, object]] = [
    {"label": "Microsoft 365", "keywords": ["microsoft 365", "office365", "login.microsoftonline"],
     "host_suffixes": [".microsoftonline.com", ".sharepoint.com", ".onmicrosoft.com"]},
    {"label": "KeyCDN", "keywords": ["keycdn"], "host_suffixes": [".kxcdn.com", ".keycdn.com"]},
    {"label": "Amazon ELB", "keywords": ["amazon elb", "elastic load balancer"],
     "host_suffixes": [".elb.amazonaws.com"]},
    {"label": "Amazon S3", "keywords": ["s3 bucket", "amazon s3"], "host_suffixes": [".s3.amazonaws.com", ".s3.us-"],
     "url_keywords": ["s3.amazonaws.com", ".s3."]},
    {"label": "CloudFront CDN", "keywords": ["cloudfront"], "host_suffixes": [".cloudfront.net"]},
    {"label": "Akamai", "keywords": ["akamaized", "akamaitechnologies", "akamai"]},
    {"label": "Fastly", "keywords": ["fastly"]},
    {"label": "Cloudflare", "keywords": ["cloudflare", "cf-ray"]},
    {"label": "Azure App Service", "host_suffixes": [".azurewebsites.net"]},
    {"label": "Google Cloud Storage", "host_suffixes": [".storage.googleapis.com"]},
]

_prep_signature_list(SOFTWARE_SIGNATURES)
_prep_signature_list(THIRD_PARTY_SIGNATURES)


def normalize_hostname(value: str) -> str:
    if not value:
        return ""
    host = value.strip().lower()
    host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", host)
    if "/" in host:
        host = host.split("/", 1)[0]
    if "?" in host:
        host = host.split("?", 1)[0]
    if "#" in host:
        host = host.split("#", 1)[0]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.lstrip("*.").strip(".")
    if not host or host in {"localhost"}:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    if not HOSTNAME_TOKEN_RE.match(host):
        return ""
    return host


def extract_hostnames(text: str) -> List[str]:
    hosts: Set[str] = set()
    if not text:
        return []
    for match in HOST_RE.finditer(text):
        host = normalize_hostname(match.group(0))
        if host:
            hosts.add(host)
    return sorted(hosts)


def extract_ips(*cells: str) -> List[str]:
    ips: Set[str] = set()
    for cell in cells:
        if not cell:
            continue
        for match in IPV4_RE.finditer(cell):
            ips.add(match.group(0))
        for match in IPV6_RE.finditer(cell):
            try:
                normalized = str(ipaddress.ip_address(match.group(0)))
                ips.add(normalized)
            except ValueError:
                continue
    return sorted(ips)


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = [match.group(0).strip().rstrip(").,") for match in URL_RE.finditer(text)]
    return urls


PORT_TOKEN_RE = re.compile(
    r"(?:(tcp|udp)\s*/\s*(\d+)|(\d+)\s*/\s*(tcp|udp))",
    re.IGNORECASE,
)


def parse_ports(cell: str) -> List[Tuple[str, int]]:
    ports: Set[Tuple[str, int]] = set()
    if not cell:
        return []
    for match in PORT_TOKEN_RE.finditer(cell):
        proto = match.group(1) or match.group(4)
        port = match.group(2) or match.group(3)
        if not proto or not port:
            continue
        try:
            ports.add((proto.lower(), int(port)))
        except ValueError:
            continue
    return sorted(ports)


def registrable_domain(host: str) -> str:
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    if tldextract:
        result = tldextract.extract(host)
        if result.domain and result.suffix:
            return f"{result.domain}.{result.suffix}".lower()
        return host
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def read_csv_records(path: str) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            normalized = { (key or "").strip(): (value or "").strip() for key, value in row.items() if key }
            lookup = {key.lower(): key for key in normalized}

            def pick(*candidates: str) -> str:
                for candidate in candidates:
                    if candidate in normalized and normalized[candidate]:
                        return normalized[candidate]
                    lc = candidate.lower()
                    if lc in lookup:
                        val = normalized[lookup[lc]]
                        if val:
                            return val
                return ""

            dns_cell = pick("DNS", "FQDN", "Host", "Hosts", "Hostname")
            ip_cell = pick("IP / Hosting Provider", "IP", "Address", "Resolved IP")
            ports_cell = pick("Ports", "Port")
            nuclei = pick("Nuclei", "Nuclei Findings")
            notes = pick("Notes", "Notes and Screenshots", "Comments", "Screenshot", "Details")
            extra = pick("Screenshot", "Screenshot Links")
            provider = pick("Hosting Provider", "Provider")

            hosts = extract_hostnames(dns_cell)
            ips = extract_ips(dns_cell, ip_cell, notes)
            ports = parse_ports(ports_cell)
            urls = extract_urls(" ".join(filter(None, [notes, nuclei])))
            text_parts = [dns_cell, ip_cell, provider, ports_cell, nuclei, notes, extra]
            combined = " ".join(part for part in text_parts if part)
            record = {
                "id": f"{os.path.basename(path)}:{idx}",
                "source": path,
                "hosts": hosts,
                "ips": ips,
                "ports": ports,
                "notes": notes,
                "nuclei": nuclei,
                "combined_text": combined.lower(),
                "combined_text_raw": combined,
                "urls": urls,
            }
            records.append(record)
    return records


def read_html_records(path: str) -> List[Dict[str, object]]:
    if BeautifulSoup is None:
        raise RuntimeError("beautifulsoup4 is required to parse HTML reports")
    records: List[Dict[str, object]] = []
    with open(path, encoding="utf-8") as handle:
        soup = BeautifulSoup(handle, "html.parser")
    table = soup.find("table")
    if not table:
        return records
    rows = table.find_all("tr")
    for idx, row in enumerate(rows, start=1):
        cells = row.find_all("td")
        if len(cells) < 4:
            continue
        dns = cells[0].get_text(" ", strip=True)
        ip_text = cells[1].get_text(" ", strip=True)
        ports_cell = cells[2].get_text(" ", strip=True)
        notes = cells[3].get_text("\n", strip=True)
        hosts = extract_hostnames(dns)
        ips = extract_ips(ip_text, notes)
        ports = parse_ports(ports_cell)
        urls = extract_urls(notes)
        combined = " ".join(part for part in [dns, ip_text, ports_cell, notes] if part)
        record = {
            "id": f"{os.path.basename(path)}:{idx}",
            "source": path,
            "hosts": hosts,
            "ips": ips,
            "ports": ports,
            "notes": notes,
            "nuclei": "",
            "combined_text": combined.lower(),
            "combined_text_raw": combined,
            "urls": urls,
        }
        records.append(record)
    return records


def load_records(paths: Sequence[str]) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    for path in paths:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            records.extend(read_csv_records(path))
        elif ext in {".htm", ".html"}:
            records.extend(read_html_records(path))
        else:
            raise RuntimeError(f"Unsupported input type for {path}; supply CSV or HTML")
    return records


def get_url_host(url: str) -> str:
    if not url:
        return ""
    host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url)
    return normalize_hostname(host.split("/")[0])


class StatsCollector:
    def __init__(self) -> None:
        self.records: List[Dict[str, object]] = []
        self.record_sources: Counter = Counter()
        self.hosts: Set[str] = set()
        self.host_domain: Dict[str, str] = {}
        self.ips: Set[str] = set()
        self.port_counter: Counter = Counter()
        self.software_hits: Dict[str, Set[str]] = defaultdict(set)
        self.software_examples: Dict[str, str] = {}
        self.third_party_hits: Dict[str, Set[str]] = defaultdict(set)
        self.third_party_examples: Dict[str, str] = {}
        self.assets: Set[str] = set()
        self.asset_ports: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)

    def add_record(self, record: Dict[str, object]) -> None:
        self.records.append(record)
        self.record_sources[record["source"]] += 1  # type: ignore
        combined_text = record.get("combined_text", "")
        combined_text_raw = record.get("combined_text_raw", "")
        ports = set(record.get("ports", []))  # type: ignore
        urls: List[str] = record.get("urls", [])  # type: ignore
        record_id = record.get("id") or f"row-{len(self.records)}"

        for proto, port in ports:
            self.port_counter[(proto, port)] += 1

        for ip in record.get("ips", []):  # type: ignore
            self.ips.add(ip)

        hosts = record.get("hosts", [])  # type: ignore
        normalized_hosts = []
        if hosts:
            for host in hosts:
                cleaned = normalize_hostname(host)
                if cleaned:
                    normalized_hosts.append(cleaned)
                    self._process_host(cleaned, record_id, combined_text, combined_text_raw, ports, urls)
        if not normalized_hosts:
            self._detect(None, record_id, combined_text, combined_text_raw, ports, urls)

        asset_ids = normalized_hosts or [record_id]
        for asset in asset_ids:
            self.assets.add(asset)
            if ports:
                self.asset_ports[asset].update(ports)

    def _process_host(
        self,
        host: str,
        record_id: str,
        combined_text: str,
        combined_text_raw: str,
        ports: Set[Tuple[str, int]],
        urls: List[str],
    ) -> None:
        if not host:
            return
        self.hosts.add(host)
        domain = registrable_domain(host)
        if domain:
            self.host_domain[host] = domain
        self._detect(host, record_id, combined_text, combined_text_raw, ports, urls)

    def _record_hit(
        self,
        container: Dict[str, Set[str]],
        examples: Dict[str, str],
        label: str,
        record_id: str,
        example: Optional[str] = None,
    ) -> None:
        container[label].add(record_id)
        if example and label not in examples:
            examples[label] = example

    def _detect(
        self,
        host: Optional[str],
        record_id: str,
        combined_text: str,
        combined_text_raw: str,
        ports: Set[Tuple[str, int]],
        urls: List[str],
    ) -> None:
        text_lower = (combined_text or "").lower()
        text_raw = combined_text_raw or ""
        for signature in SOFTWARE_SIGNATURES:
            if self._signature_matches(signature, text_lower, text_raw, ports, urls, host):
                example = host or self._pick_example(signature, urls)
                self._record_hit(self.software_hits, self.software_examples, signature["label"], record_id, example)  # type: ignore
        for signature in THIRD_PARTY_SIGNATURES:
            if self._signature_matches(signature, text_lower, text_raw, ports, urls, host):
                example = self._pick_example(signature, urls, host)
                self._record_hit(self.third_party_hits, self.third_party_examples, signature["label"], record_id, example)  # type: ignore

    @staticmethod
    def _pick_example(signature: Dict[str, object], urls: List[str], host: Optional[str] = None) -> Optional[str]:
        if host:
            return host
        if urls:
            return urls[0]
        return None

    @staticmethod
    def _signature_matches(
        signature: Dict[str, object],
        text_lower: str,
        text_raw: str,
        ports: Set[Tuple[str, int]],
        urls: List[str],
        host: Optional[str],
    ) -> bool:
        keywords: List[str] = signature.get("keywords", [])  # type: ignore
        if keywords and any(keyword in text_lower for keyword in keywords):
            return True
        patterns = signature.get("patterns")  # type: ignore
        if patterns:
            for pattern in patterns:
                if pattern.search(text_raw):
                    return True
        sig_ports: Set[Tuple[str, int]] = signature.get("ports", set())  # type: ignore
        if sig_ports and ports and sig_ports.intersection(ports):
            return True
        url_keywords: List[str] = signature.get("url_keywords", [])  # type: ignore
        if url_keywords:
            for url in urls:
                lower = url.lower()
                if any(keyword in lower for keyword in url_keywords):
                    return True
        host_suffixes: List[str] = signature.get("host_suffixes", [])  # type: ignore
        if host_suffixes:
            if host and any(host.endswith(suffix) for suffix in host_suffixes):
                return True
            for url in urls:
                url_host = get_url_host(url)
                if url_host and any(url_host.endswith(suffix) for suffix in host_suffixes):
                    return True
        return False

    @property
    def domain_count(self) -> int:
        return len(set(self.host_domain.values()))

    @property
    def subdomain_count(self) -> int:
        count = 0
        for host, domain in self.host_domain.items():
            if domain and host != domain:
                count += 1
        return count

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def ip_count(self) -> int:
        return len(self.ips)

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    @property
    def active_asset_count(self) -> int:
        return sum(1 for asset in self.assets if self.asset_ports.get(asset))

    @property
    def inactive_asset_count(self) -> int:
        return self.asset_count - self.active_asset_count


def pluralize(count: int, singular: str, plural: Optional[str] = None) -> str:
    if count == 1:
        return f"1 {singular}"
    label = plural or f"{singular}s"
    return f"{count} {label}"


def format_top_items(counter: Counter, limit: int, formatter) -> List[str]:
    return [
        formatter(item, count)
        for item, count in counter.most_common(limit)
        if count > 0
    ]


def build_summary_lines(stats: StatsCollector, top_services: int, top_ports: int, top_third_party: int) -> List[str]:
    lines = []
    if stats.asset_count:
        lines.append(
            f"{pluralize(stats.asset_count, 'asset')} total; "
            f"{pluralize(stats.active_asset_count, 'asset', 'assets')} with listening ports; "
            f"{pluralize(stats.inactive_asset_count, 'asset', 'assets')} without listening ports"
        )
    lines.append(f"{pluralize(stats.domain_count, 'domain')}, {pluralize(stats.subdomain_count, 'subdomain')}")
    lines.append(f"{pluralize(stats.ip_count, 'unique active IP address', 'unique active IP addresses')}")

    software_counts = sorted(stats.software_hits.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    top_labels:Set[str]=set()
    for label, entries in software_counts[:top_services]:
        lines.append(f"{pluralize(len(entries), 'instance')} of {label}")
        top_labels.add(label)
    highlight_segments=[]
    for label in PRIORITY_SOFTWARE:
        if label in top_labels:
            continue
        entries=stats.software_hits.get(label)
        if entries:
            highlight_segments.append(f"{pluralize(len(entries), 'instance')} of {label}")
    if highlight_segments:
        lines.append(f"Other notable platforms: {', '.join(highlight_segments)}")

    if stats.port_counter:
        port_lines = []
        for (proto, port), count in stats.port_counter.most_common(top_ports):
            port_lines.append(f"{proto}/{port} ({count})")
        if port_lines:
            lines.append(f"Common observed ports: {', '.join(port_lines)}")

    third_party = sorted(stats.third_party_hits.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:top_third_party]
    if third_party:
        labels = []
        for label, entries in third_party:
            snippet = label
            example = stats.third_party_examples.get(label)
            if example:
                snippet = f"{label} ({example})"
            labels.append(snippet)
        lines.append(f"Third-party services include {', '.join(labels)}")
    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize new-recon CSV or screenshot HTML output.")
    parser.add_argument("inputs", nargs="+", help="CSV or HTML files produced by new-recon tooling.")
    parser.add_argument("--top-services", type=int, default=6, help="How many software hits to list (default 6).")
    parser.add_argument("--top-ports", type=int, default=5, help="How many ports to highlight (default 5).")
    parser.add_argument("--top-third-party", type=int, default=5, help="How many third-party services to mention (default 5).")
    parser.add_argument("--output-html", help="Aggregated HTML report path (default: derive _output.html).")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    records = load_records(args.inputs)
    if not records:
        print("[!] No records parsed; double-check the inputs.", file=sys.stderr)
        sys.exit(1)
    stats = StatsCollector()
    for record in records:
        stats.add_record(record)
    summary_lines = build_summary_lines(stats, args.top_services, args.top_ports, args.top_third_party)
    print("\nKey stats:")
    for line in summary_lines:
        print(f" - {line}")

    output_html = derive_output_html_path(args.inputs[0], args.output_html)
    html_items = "".join(f"<li>{html.escape(line)}</li>" for line in summary_lines)
    append_html_section(output_html, "Recon Stats", f"<ul class='stats-list'>{html_items}</ul>")
    print(f"[+] Appended stats summary to {output_html}")

if __name__ == "__main__":
    main()
