#!/usr/bin/env python3
"""
recon-ai-notes.py

Purpose:
  Post-process a CSV produced by new-recon.py to fill the Notes column by:
    - Curling each hostname/IP once on a likely web port
    - Sending curl output (+ optional Nuclei context) to an LLM
    - Writing short (<=100 chars) notes per row, with a hybrid mode that can
      collapse identical hosts into one combined summary
      OR return per-host notes (deterministic JSON).

CSV columns (from new-recon.py):
  DNS, IP / Hosting Provider, Ports, Nuclei, Notes

Key behavior:
  - Skips curl when Ports is "None" (case-insensitive) or has no known web ports.
  - Known web ports: 443,80,8080,8443,8008,8000,8888,3000,5000
  - DNS blank -> curl the IP parsed from "IP / Hosting Provider" (IPv4/IPv6).
  - One curl per hostname (no per-row dedupe). If multiple hosts in a row:
      * Hybrid JSON lets the LLM combine identical behavior into one sentence,
        else returns per-host notes.
  - Notes: <=100 chars; do NOT mention cert issuers/self-signed, HSTS, CSP, Google Analytics.
  - Opens with utf-8-sig; normalizes header names.
  - Overwrites the input CSV by default; use -o to write elsewhere.

Usage:
  python recon-ai-notes.py recon.csv
  python recon-ai-notes.py recon.csv -o recon_with_notes.csv
  OPENAI_API_KEY=... python recon-ai-notes.py recon.csv --model gpt-4.1

Dependencies:
  - curl on PATH
  - Python 3.10+
  - pip install openai>=1.50.0
  - (optional) pip install alive-progress
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from typing import List, Tuple, Dict, Optional

# ---- Optional progress bar ----
_HAS_ALIVE = False
try:
    from alive_progress import alive_it
    _HAS_ALIVE = True
except Exception:
    _HAS_ALIVE = False

# ---- OpenAI client helper ----
def get_openai_client():
    try:
        from openai import OpenAI
    except ImportError:
        sys.stderr.write("[!] The 'openai' package is required. Install with: pip install openai>=1.50.0\n")
        sys.exit(1)
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.stderr.write("[!] Please set OPENAI_API_KEY in your environment.\n")
        sys.exit(1)
    client = OpenAI(api_key=api_key)
    return client

# ---- Utility parsing ----
WEB_PORTS = [443, 80, 8080, 8443, 8008, 8000, 8888, 3000, 5000]
PORT_PREFERENCE = [443, 80, 8080, 8443, 8008, 8000, 8888, 3000, 5000]
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6_RE = re.compile(r"\b([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

def parse_ports_cell(ports_cell: str):
    if ports_cell is None:
        return []
    s = ports_cell.strip()
    if s.lower() == "none":
        return ["NONE"]  # sentinel
    ports = []
    for token in s.split(","):
        token = token.strip()
        m = re.search(r"tcp/(\d+)", token, re.IGNORECASE)
        if m:
            try:
                ports.append(int(m.group(1)))
            except ValueError:
                pass
    return ports

def choose_scheme_and_port(ports) -> Optional[Tuple[str, int]]:
    """
    Return (scheme, port) or None if no web port should be used.
    - If sentinel "NONE" present, return None.
    - Only pick from WEB_PORTS; otherwise None.
    """
    if "NONE" in ports:
        return None
    webset = [p for p in ports if isinstance(p, int) and p in WEB_PORTS]
    if not webset:
        return None
    for p in PORT_PREFERENCE:
        if p in webset:
            return ("https", 443) if p == 443 else ("http", p)
    return None

def split_hostnames(dns_cell: str, max_hosts:int) -> List[str]:
    if not dns_cell:
        return []
    raw = re.split(r"[,\s;]+", dns_cell.strip())
    seen = set()
    hosts = []
    for h in raw:
        if not h:
            continue
        if h not in seen:
            seen.add(h)
            hosts.append(h)
        if len(hosts) >= max_hosts:
            break
    return hosts

def extract_ip_from_provider_cell(cell: str) -> Optional[str]:
    """
    Pulls the first IPv4 or IPv6 from the 'IP / Hosting Provider' cell.
    Returns None if no IP is present (e.g., 'Cloudflare', 'Azure').
    """
    if not cell:
        return None
    m4 = IPV4_RE.search(cell)
    if m4:
        return m4.group(0)
    m6 = IPV6_RE.search(cell)
    if m6:
        return m6.group(0)
    return None

# ---- Curl execution ----
def run_curl(host_or_ip: str, scheme: str, port: int, timeout: int, user_agent: str, max_bytes: int) -> Dict[str, str]:
    url = f"{scheme}://{host_or_ip}"
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        url = f"{scheme}://{host_or_ip}:{port}"

    cmd = [
        "curl",
        "-kvsS",
        "-i",
        "--max-redirs", "0",
        "-m", str(timeout),
        "-A", user_agent,
        url,
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"url": url, "stdout": "", "stderr": "[curl] Timeout", "rc": "124"}

    if len(stdout) > max_bytes:
        stdout = stdout[:max_bytes] + f"\n[...truncated to {max_bytes} bytes...]"

    return {"url": url, "stdout": stdout, "stderr": stderr, "rc": str(proc.returncode)}

# ---- Local fallback heuristics (<=100 chars, no HSTS/CSP/GA or cert issuer) ----
_HTTP_STATUS_RE = re.compile(r"^HTTP/\d\.\d\s+(\d{3})", re.MULTILINE)
_LOCATION_RE    = re.compile(r"^Location:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_PHP_RE         = re.compile(r"(?i)\bphp\b|x-powered-by:\s*php", re.IGNORECASE)
_WP_RE          = re.compile(r"(?i)wordpress")
_ASPNET_RE      = re.compile(r"(?i)asp\.net|x-aspnet", re.IGNORECASE)
_CF_RE          = re.compile(r"(?i)cloudflare|cf-ray|cf-cache-status")
_ENTRA_RE       = re.compile(r"(?i)microsoftonline\.com|login\.microsoftonline|login\.microsoft\.com|entra", re.IGNORECASE)


def _shorten(s: str, n: int = 100) -> str:
    return s[:n]

def local_fallback_note(res: dict) -> str:
    stdout = res.get("stdout") or ""
    stderr = res.get("stderr") or ""
    blob = stdout + "\n" + stderr

    m = _HTTP_STATUS_RE.search(stdout)
    code = m.group(1) if m else None

    loc = ""
    lm = _LOCATION_RE.search(stdout)
    if lm:
        loc = lm.group(1)
        loc = re.sub(r"^https?://", "", loc)  # shorter

    parts = []
    if code and loc:
        parts.append(f"{code} -> {loc}")
    elif code:
        parts.append(code)

    # framework/CMS clues (avoid HSTS/CSP/GA/cert chatter)
    if _WP_RE.search(blob):
        parts.append("WordPress")
    elif _PHP_RE.search(blob):
        parts.append("PHP")
    elif _ASPNET_RE.search(blob):
        parts.append("ASP.NET")

    if _ENTRA_RE.search(blob):
        parts.append("IdP redirect")
    if _CF_RE.search(blob):
        parts.append("Cloudflare")

    if not parts:
        if "Timeout" in stderr:
            parts.append("Timeout")
        elif code:
            parts.append(code)
        else:
            return ""  # nothing obvious

    return _shorten(" ".join(parts))

# ---- LLM (Hybrid JSON mode + chunked per-host fallback) ----
SYSTEM_PROMPT = """You are a terse web reconnaissance summarizer.

You will receive curl -kv results for K hostnames from one CSV row.
Decide if they behave identically. Return ONLY valid JSON in one of two forms:

COMBINED (all hosts behave the same):
{"mode":"combined","summary":"..."}
PER_HOST (hosts differ in behavior):
{"mode":"per_host","notes":["...","..."]}

Rules:
- In PER_HOST mode, DO NOT include hostnames in the notes; return note bodies only.
- In COMBINED mode, you may say "Both hosts ..." or "All N hosts ...".
- Keep each output string <=100 chars.
- Prefer ":" to separate host and note if you include hostnames.
- For redirects show status + target: "301 -> example.com/path" (omit scheme).
- Include clear errors (403/404/429/500/502/503/520…), CDN/WAF (e.g., Cloudflare),
  obvious frameworks/CMS (WordPress, PHP, ASP.NET), IdP redirects (Microsoft/Entra, Okta, Keycloak).
- Do NOT mention: certificate issuers or self-signed, HSTS, CSP, Google Analytics.
- For COMBINED, make a single compact human-readable sentence, e.g.:
  "Both hosts 301 -> example.com/x/y (Cloudflare)" (or "All N hosts ..." if >2).
- For PER_HOST, return exactly K strings in order, one per host. Be concise.

Return JSON only, no extra text.
"""


def build_user_prompt(host_results: List[Dict[str, str]], nuclei_hint: Optional[str] = None) -> str:
    lines = [f"K={len(host_results)}"]
    if nuclei_hint:
        lines.append(f"NUCLEI: {nuclei_hint.strip()}")
    lines.append("")  # spacer
    for res in host_results:
        part = [
            f"HOST: {res['url']}",
            f"RETURNCODE: {res['rc']}",
        ]
        if res.get("stderr"):
            part.append("STDERR:\n" + res["stderr"].strip())
        if res.get("stdout"):
            part.append("STDOUT:\n" + res["stdout"].strip())
        lines.append("\n".join(part))
    return "\n\n---\n\n".join(lines)

def analyze_row_hybrid(client, model: str, host_results: List[Dict[str, str]], nuclei_hint: Optional[str],
                       retries: int = 3, backoff: float = 1.6) -> Dict:
    """
    Returns a dict either:
      {"mode":"combined","summary":"..."}  OR
      {"mode":"per_host","notes":[str, ...]}  (len == K)
    On failure, returns empty dict -> caller should fallback locally.
    """
    prompt = build_user_prompt(host_results, nuclei_hint)
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=350,
            )
            txt = resp.choices[0].message.content.strip()
            obj = json.loads(txt)
            mode = obj.get("mode", "")
            if mode == "combined" and isinstance(obj.get("summary", ""), str):
                return {"mode": "combined", "summary": obj["summary"][:100]}
            if mode == "per_host" and isinstance(obj.get("notes"), list):
                notes = [(n or "")[:100] if isinstance(n, str) else "" for n in obj["notes"]]
                if len(notes) == len(host_results):
                    return {"mode": "per_host", "notes": notes}
        except Exception:
            time.sleep(backoff ** attempt)
    return {}

def analyze_chunk_with_openai(client, model: str, host_results: List[Dict[str, str]],
                              nuclei_hint: Optional[str], retries: int = 3,
                              backoff: float = 1.6) -> List[str]:
    """
    Deterministic per-chunk analyzer that returns a list of strings (one per host).
    Uses a simpler JSON contract: {"notes":["...", "..."]} with EXACT length K.
    """
    simple_prompt = """You are a terse web reconnaissance summarizer.
Return ONLY this JSON: {"notes":["...", "...", ...]} with EXACTLY K strings (in order).
Each note <=100 chars. Include HTTP status/redirects, clear errors, CDN/WAF, CMS/framework,
IdP redirects. Do NOT mention cert issuers/self-signed, HSTS, CSP, Google Analytics."""
    user_prompt = build_user_prompt(host_results, nuclei_hint)
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": simple_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=350,
            )
            txt = resp.choices[0].message.content.strip()
            obj = json.loads(txt)
            notes = obj.get("notes", [])
            if isinstance(notes, list) and len(notes) == len(host_results):
                return [(n or "")[:100] if isinstance(n, str) else "" for n in notes]
        except Exception:
            time.sleep(backoff ** attempt)
    return [""] * len(host_results)

# ---- CSV helpers ----
BASE_COLS = ["DNS", "IP / Hosting Provider", "Ports", "Nuclei"]
NOTES_COL = "Notes"

def normalize_fieldnames(fieldnames):
    return [fn.strip() if isinstance(fn, str) else fn for fn in (fieldnames or [])]

def ensure_required_fields(fieldnames):
    missing = [col for col in BASE_COLS if col not in fieldnames]
    if missing:
        sys.stderr.write(f"[!] Missing required column(s): {', '.join(missing)}\n")
        sys.exit(1)

# ---- Main processing ----
def process_csv(input_path: str, output_path: Optional[str], max_hosts_per_row: int, timeout: int,
                ua: str, max_bytes: int, model: str, show_headers: bool):
    client = get_openai_client()

    with open(input_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = normalize_fieldnames(reader.fieldnames)
        if show_headers:
            print("Detected headers:", fieldnames)
        reader.fieldnames = fieldnames

        ensure_required_fields(fieldnames)
        if NOTES_COL not in fieldnames:
            fieldnames.append(NOTES_COL)

        rows = list(reader)

    iter_rows = alive_it(rows, title="Probing & analyzing hosts") if _HAS_ALIVE else rows
    total = len(rows)
    out_rows = []

    for idx, row in enumerate(iter_rows):
        dns_cell = (row.get("DNS") or "").strip()
        provider_cell = (row.get("IP / Hosting Provider") or "").strip()
        ports_cell = row.get("Ports", "")
        nuclei_hint = (row.get("Nuclei") or "").strip()

        # Parse ports and decide if we should skip entirely
        ports = parse_ports_cell(ports_cell)
        choice = choose_scheme_and_port(ports)
        if choice is None:
            # Skip: Ports was "None" or no web ports present; leave Notes unchanged
            out_rows.append(row)
            if _HAS_ALIVE:
                iter_rows.text = f"{idx+1}/{total} skip (non-web)"
            continue

        scheme, port = choice

        # Resolve target list
        hostnames = split_hostnames(dns_cell, max_hosts_per_row)
        if not hostnames:
            ip = extract_ip_from_provider_cell(provider_cell)
            if not ip:
                # Still nothing to hit; leave Notes unchanged
                out_rows.append(row)
                if _HAS_ALIVE:
                    iter_rows.text = f"{idx+1}/{total} skip (no DNS/IP)"
                continue
            hostnames = [ip]

        if _HAS_ALIVE:
            iter_rows.text = f"{idx+1}/{total} {hostnames[0][:50]}"

        # Probe each hostname once
        host_results = []
        for hostname in hostnames:
            if _HAS_ALIVE:
                iter_rows.text = f"{idx+1}/{total} curl {hostname}:{port}"
            res = run_curl(
                host_or_ip=hostname,
                scheme=scheme,
                port=port,
                timeout=timeout,
                user_agent=ua,
                max_bytes=max_bytes,
            )
            host_results.append(res)

        # Analyze: hybrid for small rows (<=3 hosts), else chunked per-host
        notes_all: List[str] = []
        if len(host_results) <= 3:
            obj = analyze_row_hybrid(client, model, host_results, nuclei_hint)
            if obj.get("mode") == "combined":
                # Use the single combined summary as Notes
                row[NOTES_COL] = obj["summary"]
                out_rows.append(row)
                continue
            elif obj.get("mode") == "per_host":
                notes_all = obj["notes"]
            else:
                # Hybrid failed -> local fallback per host
                notes_all = [local_fallback_note(hr) or "No response" for hr in host_results]
        else:
            # Chunked per-host deterministic path (no combining across chunks)
            CHUNK_SIZE = 2
            for i in range(0, len(host_results), CHUNK_SIZE):
                chunk = host_results[i:i+CHUNK_SIZE]
                notes = analyze_chunk_with_openai(client, model, chunk, nuclei_hint)
                # local fallback for blanks
                for j, n in enumerate(notes):
                    if not n:
                        notes[j] = local_fallback_note(chunk[j]) or "No response"
                notes_all.extend(notes)

        # If multiple hosts in the row, label each note with hostname using ":"
        if len(hostnames) > 1:
            labeled = [f"{hn}: {note}" for hn, note in zip(hostnames, notes_all)]
            combined_notes = " ; ".join(labeled)
        else:
            combined_notes = notes_all[0] if notes_all else "No response"

        row[NOTES_COL] = combined_notes
        out_rows.append(row)

    # Write output (in-place by default)
    write_path = output_path or input_path
    with open(write_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"[+] Wrote: {write_path}")

# ---- CLI ----
def main():
    parser = argparse.ArgumentParser(
        description="Fill the Notes column of a CSV generated by new-recon.py using curl + LLM hybrid analysis."
    )
    parser.add_argument("input_csv", help="Path to CSV from new-recon.py (columns: DNS, IP / Hosting Provider, Ports, Nuclei, Notes)")
    parser.add_argument("-o", "--output-csv", help="Optional output CSV path. If omitted, the input file is overwritten in place.")
    parser.add_argument("--max-hosts-per-row", type=int, default=3, help="Max hostnames to probe per row (parsed from DNS cell). Default: 3")
    parser.add_argument("--timeout", type=int, default=15, help="Curl timeout seconds per request. Default: 15")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (compatible; ReconBot/1.0)", help="User-Agent for curl")
    parser.add_argument("--max-bytes", type=int, default=2048, help="Truncate stdout to this many bytes. Default: 2048")
    parser.add_argument("--model", default="gpt-4.1", help="OpenAI model to use (e.g., gpt-4.1, gpt-4o)")
    parser.add_argument("--show-headers", action="store_true", help="Print detected CSV header names and continue")
    args = parser.parse_args()

    process_csv(
        input_path=args.input_csv,
        output_path=args.output_csv,
        max_hosts_per_row=args.max_hosts_per_row,
        timeout=args.timeout,
        ua=args.user_agent,
        max_bytes=args.max_bytes,
        model=args.model,
        show_headers=args.show_headers,
    )

if __name__ == "__main__":
    main()
