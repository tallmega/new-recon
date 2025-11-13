#!/usr/bin/env python3
"""
recon-ai-notes.py  (LLM per-host + one-hop follow + version parsing + local grouping)

Usage:
  OPENAI_API_KEY=... python recon-ai-notes.py input.csv
  OPENAI_API_KEY=... python recon-ai-notes.py input.csv -o output.csv

CSV columns (from new-recon.py):
  DNS, IP / Hosting Provider, Ports, Nuclei, Notes
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlparse
from typing import List, Tuple, Dict, Optional

# ---------- Optional progress bar ----------
_HAS_ALIVE = False
try:
    from alive_progress import alive_it
    _HAS_ALIVE = True
except Exception:
    _HAS_ALIVE = False

# ---------- OpenAI client ----------
def get_openai_client():
    try:
        from openai import OpenAI
    except ImportError:
        sys.stderr.write("[!] Install: pip install openai>=1.50.0\n")
        sys.exit(1)
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.stderr.write("[!] Please set OPENAI_API_KEY in your environment.\n")
        sys.exit(1)
    return OpenAI(api_key=api_key)

# ---------- Constants / Regex ----------
WEB_PORTS = [443, 80, 8080, 8443, 8008, 8000, 8888, 3000, 5000]
PORT_PREFERENCE = [443, 8443, 9443, 10443, 80, 8080, 8000, 8888, 3000, 5000]
HTTPS_PORTS = {443, 4443, 5443, 6443, 7443, 8443, 9443, 10443}

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6_RE = re.compile(r"\b([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

_HTTP_STATUS_RE = re.compile(r"^HTTP/\d\.\d\s+(\d{3})", re.MULTILINE)
_LOCATION_RE    = re.compile(r"^Location:\s*(\S+)", re.IGNORECASE | re.MULTILINE)

# tech/version hints
_PHP_RE         = re.compile(r"(?i)\bphp\b|x-powered-by:\s*php", re.IGNORECASE)
_WP_RE          = re.compile(r"(?i)wordpress")
_ASPNET_RE      = re.compile(r"(?i)asp\.net|x-aspnet", re.IGNORECASE)
_CF_RE          = re.compile(r"(?i)cloudflare|cf-ray|cf-cache-status")
_IDP_RE         = re.compile(r"(?i)microsoftonline\.com|login\.microsoftonline|login\.microsoft\.com|entra|okta|keycloak")

SERVER_HDR_RE   = re.compile(r"^Server:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
X_POWERED_RE    = re.compile(r"^X-Powered-By:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
X_ASPNET_VER_RE = re.compile(r"^X-AspNet-Version:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
X_ASPNETMVC_VER_RE = re.compile(r"^X-AspNetMvc-Version:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
X_GENERATOR_RE  = re.compile(r"^X-Generator:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
META_WP_GEN_RE  = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9.]+)["\']', re.IGNORECASE)
PHP_VER_IN_XPB  = re.compile(r"PHP/?\s*([0-9.]+)", re.IGNORECASE)
IIS_VER_IN_SERVER = re.compile(r"Microsoft-IIS/([0-9.]+)", re.IGNORECASE)
ASP_NET_IN_XPB  = re.compile(r"ASP\.NET(?:\s*([0-9.]+))?", re.IGNORECASE)

HTTP_LABEL_MAP = {
    "HTTP/2 200": "200 OK",
    "HTTP/2 403": "403 Forbidden",
    "HTTP/2 404": "404 Not Found",
    "HTTP/2 429": "429 Too Many Requests",
    "HTTP/2 500": "500 Internal Server Error",
    "HTTP/2 502": "502 Bad Gateway",
    "HTTP/2 503": "503 Service Unavailable",
}

TECH_TOKEN_RES = [
    re.compile(r"\bWordPress\s*[0-9.]*", re.I),
    re.compile(r"\bPHP\s*[0-9.]*", re.I),
    re.compile(r"\bASP\.NET(?:\s*[0-9.]+)?", re.I),
    re.compile(r"\bASP\.NET\s*MVC\s*[0-9.]+", re.I),
    re.compile(r"\bMicrosoft-IIS/[0-9.]+", re.I),
    re.compile(r"\bnginx\b", re.I),
    re.compile(r"\bApache\b", re.I),
    re.compile(r"\bCloudflare\b", re.I),
    re.compile(r"\bIdP redirect\b", re.I),
]

# ---------- Helpers ----------
def extract_tech_from_note(note: str) -> str:
    """
    Pull concise tech bits from a representative note (e.g., '200 OK, ASP.NET 4.0.30319, Microsoft-IIS/10.0')
    and return a short 'ASP.NET 4.0.30319, Microsoft-IIS/10.0' string.
    """
    if not note:
        return ""
    # Remove leading status/redirect wording to reduce noise
    note = re.sub(r"^\s*\d{3}(\s+\w+)?\s*,?\s*", "", note)            # drop '200 OK,' etc.
    note = re.sub(r"^\s*3\d\d\s*->\s*\S+\s*,?\s*", "", note)          # drop '301 -> target,' etc.

    found = []
    seen = set()
    for rx in TECH_TOKEN_RES:
        for m in rx.finditer(note):
            tok = m.group(0).strip().rstrip(",")
            key = tok.lower()
            if key not in seen:
                seen.add(key)
                found.append(tok)
    return ", ".join(found)

def parse_ports_cell(ports_cell: str):
    if ports_cell is None:
        return []
    s = ports_cell.strip()
    if s.lower() == "none":
        return ["NONE"]
    out = []
    for token in s.split(","):
        token = token.strip()
        m = re.search(r"tcp/(\d+)", token, re.IGNORECASE)
        if m:
            try:
                out.append(int(m.group(1)))
            except ValueError:
                pass
    return out

def choose_schemes_and_ports(ports: List[int], limit: int) -> List[Tuple[str, int]]:
    if limit <= 0 or "NONE" in ports:
        return []
    webset = [p for p in ports if isinstance(p, int) and p in WEB_PORTS]
    if not webset:
        return []
    ordered = []
    seen = set()
    for pref in PORT_PREFERENCE:
        if pref in webset and pref not in seen:
            ordered.append(pref)
            seen.add(pref)
    for p in sorted(set(webset)):
        if p not in seen:
            ordered.append(p)
            seen.add(p)
    combos = []
    for port in ordered:
        scheme = "https" if port in HTTPS_PORTS else "http"
        combos.append((scheme, port))
        if len(combos) >= limit:
            break
    return combos

def split_hosts(dns_cell: str, max_hosts:int) -> List[str]:
    if not dns_cell:
        return []
    raw = re.split(r"[,\s;]+", dns_cell.strip())
    seen, out = set(), []
    for h in raw:
        if h and h not in seen:
            seen.add(h); out.append(h)
            if len(out) >= max_hosts:
                break
    return out

def format_target_label(host: str, scheme: str, port: int) -> str:
    label = host.strip()
    if ":" in label and not label.startswith("["):
        label = f"[{label}]"
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return f"{scheme}://{label}"
    return f"{scheme}://{label}:{port}"


def summarize_path(path: str) -> str:
    if not path or path == "/":
        return ""
    path = path.strip()
    segments = path.strip("/").split("/")
    if len(segments) > 2:
        return "/" + "/".join(segments[:2]) + "/..."
    if not path.startswith("/"):
        path = "/" + path
    return path


def parse_location_target(raw: str, fallback_scheme: str, fallback_host: str) -> Tuple[str, str, str]:
    raw = (raw or "").strip()
    if not raw:
        return "", "", ""
    parsed = None
    if raw.startswith("//"):
        scheme = fallback_scheme or "https"
        parsed = urlparse(f"{scheme}:{raw}")
    elif raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
    if parsed:
        scheme = parsed.scheme or fallback_scheme or ""
        host = parsed.netloc or fallback_host or ""
        path = parsed.path or ""
        return scheme.lower(), host, path
    if raw.startswith("/"):
        return fallback_scheme or "", fallback_host or "", raw
    if "/" in raw:
        host, rest = raw.split("/", 1)
        return "", host, "/" + rest
    return fallback_scheme or "", fallback_host or "", f"/{raw}"


def summarize_redirect_display(orig_host: str, orig_scheme: str,
                               dest_scheme: str, dest_host: str, dest_path: str) -> str:
    orig_host_norm = (orig_host or "").lower()
    dest_host_norm = (dest_host or "").lower()
    path_summary = summarize_path(dest_path)
    same_host = bool(orig_host_norm and dest_host_norm and orig_host_norm == dest_host_norm)
    if same_host:
        if dest_scheme and orig_scheme and dest_scheme != orig_scheme:
            return dest_scheme
        if path_summary:
            return path_summary.lstrip("/") or "/"
        return dest_scheme or dest_host or "/"
    target = dest_host or ""
    if dest_scheme:
        target = f"{dest_scheme}://{target}" if target else dest_scheme
    if path_summary:
        target += path_summary
    return target or dest_scheme or "/"

def extract_ip_from_provider_cell(cell: str) -> Optional[str]:
    if not cell:
        return None
    m4 = IPV4_RE.search(cell)
    if m4:
        return m4.group(0)
    m6 = IPV6_RE.search(cell)
    if m6:
        return m6.group(0)
    return None

def normalize_http_label(note: str) -> str:
    if not note:
        return note
    for k, v in HTTP_LABEL_MAP.items():
        if k in note:
            note = note.replace(k, v)
    note = re.sub(r"\s+,", ",", note)
    note = re.sub(r",\s+,", ", ", note)
    return note.strip()

def safe_trunc(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    cut = max(s.rfind(" ", 0, limit), s.rfind(",", 0, limit), s.rfind(";", 0, limit), s.rfind(")", 0, limit))
    if cut < int(limit * 0.6):
        cut = limit
    return s[:cut].rstrip() + "..."

def abbreviate_hosts(hosts: List[str], maxlen: int) -> str:
    if not hosts:
        return ""
    s = ", ".join(hosts)
    if len(s) <= maxlen:
        return s
    if len(hosts) <= 2:
        return (s[:maxlen-3] + "...")
    return f"{hosts[0]}, {hosts[1]}, +{len(hosts)-2} more"

# ---------- Curl ----------
def run_curl(host_or_ip: str, scheme: str, port: int, timeout: int, user_agent: str, max_bytes: int) -> Dict[str, str]:
    url = f"{scheme}://{host_or_ip}"
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        url = f"{scheme}://{host_or_ip}:{port}"
    return run_curl_url(url, timeout, user_agent, max_bytes)

def run_curl_url(url: str, timeout: int, user_agent: str, max_bytes: int) -> Dict[str, str]:
    cmd = [
        "curl",
        "-kvsS",
        "-i",
        "--max-redirs", "0",
        "-m", str(timeout),
        "-A", user_agent,
        url,
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, encoding="utf-8", errors="replace")
    try:
        stdout, stderr = p.communicate(timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        p.kill()
        return {"url": url, "stdout": "", "stderr": "[curl] Timeout", "rc": "124"}
    if len(stdout) > max_bytes:
        stdout = stdout[:max_bytes] + f"\n[...truncated to {max_bytes} bytes...]"
    return {"url": url, "stdout": stdout, "stderr": stderr, "rc": str(p.returncode)}

def parse_status_and_location(stdout: str) -> Tuple[Optional[str], Optional[str]]:
    m_code = _HTTP_STATUS_RE.search(stdout or "")
    code = m_code.group(1) if m_code else None
    m_loc = _LOCATION_RE.search(stdout or "")
    loc = m_loc.group(1).strip() if m_loc else None
    return code, loc

# ---------- Local fallback (version-aware) ----------
def local_fallback_note(res: dict) -> str:
    # Prefer the followed page if available
    stdout = res.get("follow_stdout") or res.get("stdout") or ""
    stderr = res.get("follow_stderr") or res.get("stderr") or ""
    blob = stdout + "\n" + stderr

    m = _HTTP_STATUS_RE.search(res.get("stdout") or "")
    code = m.group(1) if m else None

    raw_loc = ""
    lm = _LOCATION_RE.search(res.get("stdout") or "")
    if lm:
        raw_loc = lm.group(1).strip()
    orig_host = (res.get("host") or "").strip().rstrip(".")
    orig_scheme = (res.get("scheme") or "").lower()

    parts = []
    if code and raw_loc and code in ("301","302","307","308"):
        dest_scheme, dest_host, dest_path = parse_location_target(raw_loc, orig_scheme, orig_host)
        display = summarize_redirect_display(orig_host, orig_scheme, dest_scheme, dest_host, dest_path)
        parts.append(f"{code} -> {display}")
    elif code:
        label = {
            "200":"200 OK",
            "301":"301 Moved",
            "302":"302 Found",
            "307":"307 Redirect",
            "308":"308 Redirect",
            "403":"403 Forbidden",
            "404":"404 Not Found",
            "429":"429 Too Many Requests",
            "500":"500 Internal Server Error",
            "502":"502 Bad Gateway",
            "503":"503 Service Unavailable",
            "520":"520 Error",
        }.get(code, code)
        parts.append(label)
    else:
        if "Timeout" in (res.get("stderr") or ""):
            parts.append("Timeout")
        else:
            parts.append("No response")

    # Versions / stacks (from followed page when present)
    server_val = ""
    m_srv = SERVER_HDR_RE.search(stdout)
    if m_srv:
        server_val = m_srv.group(1).strip()
        m_iis = IIS_VER_IN_SERVER.search(server_val)
        if m_iis:
            parts.append(f"Microsoft-IIS/{m_iis.group(1)}")
        else:
            if server_val.lower().startswith("nginx"):
                parts.append("nginx")
            elif server_val.lower().startswith("apache"):
                parts.append("Apache")

    m_xpb = X_POWERED_RE.search(stdout)
    if m_xpb:
        xpb = m_xpb.group(1)
        m_php = PHP_VER_IN_XPB.search(xpb)
        if m_php:
            parts.append(f"PHP {m_php.group(1)}")
        else:
            m_asp = ASP_NET_IN_XPB.search(xpb)
            if m_asp:
                ver = m_asp.group(1)
                parts.append(f"ASP.NET {ver}" if ver else "ASP.NET")

    m_asv = X_ASPNET_VER_RE.search(stdout)
    if m_asv:
        parts.append(f"ASP.NET {m_asv.group(1).strip()}")

    m_aspmvc = X_ASPNETMVC_VER_RE.search(stdout)
    if m_aspmvc:
        parts.append(f"ASP.NET MVC {m_aspmvc.group(1).strip()}")

    wp_ver = ""
    m_xgen = X_GENERATOR_RE.search(stdout)
    if m_xgen and "WordPress" in m_xgen.group(1):
        m_wpv = re.search(r"WordPress\s*([0-9.]+)", m_xgen.group(1), re.IGNORECASE)
        if m_wpv:
            wp_ver = m_wpv.group(1)
    if not wp_ver:
        m_meta = META_WP_GEN_RE.search(stdout)
        if m_meta:
            wp_ver = m_meta.group(1)
    if wp_ver:
        parts.append(f"WordPress {wp_ver}")
    else:
        if _WP_RE.search(stdout):
            parts.append("WordPress")

    if _CF_RE.search(blob):
        parts.append("Cloudflare")
    if _IDP_RE.search(blob):
        parts.append("IdP redirect")

    # De-dup
    seen, uniq = set(), []
    for p in parts:
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)
    return ", ".join(uniq)

# ---------- LLM (per-chunk strict per-host) ----------
SIMPLE_PROMPT = """You are a terse web reconnaissance summarizer.

Return ONLY this JSON:
{"notes":["...", "...", ...], "sigs":["...", "...", ...]}
with EXACTLY K strings in each array (in order). STRICT RULES:

- One note PER HOST. Never combine or summarize across hosts.
- Do NOT include hostnames in the notes.
- Do NOT write phrases like "Both hosts" or "All N hosts".
- Keep each note concise. Include: HTTP status, redirect target (omit scheme),
  clear errors (403/404/429/500/502/503/520), CDN/WAF (e.g., Cloudflare),
  CMS/framework AND VERSIONS when present (e.g., WordPress 6.5.5, PHP 8.1.13,
  ASP.NET 4.0.30319, Microsoft-IIS/10.0). Use response headers and meta tags:
    - Server:
    - X-Powered-By:
    - X-AspNet-Version:
    - X-AspNetMvc-Version:
    - X-Generator:
    - <meta name="generator" content="WordPress X.Y.Z">
  Identify known enterprise platforms (/global-protect/ indicates PAN-OS VPN, CSCOE indicates Cisco VPN, OWA indicates Exchange, /sonicui/ indicates SonicWall, etc.).
  Include IdP redirects (Microsoft/Entra, Okta, Keycloak) when evident.
- Do NOT mention certificate issuers or self-signed, HSTS, CSP, or Google Analytics.

"sigs" must be short grouping keys, e.g.:
  "301->www.example.com|cf", "403|cf", "200|wp6.5|php8.1", "noresp", "timeout", "302->login.example.com|idp|cf"

Where tags may include:
  |cf (Cloudflare), |idp (IdP redirect), |wp<ver>, |php<ver>, |asp<ver>, |iis<ver>

Return JSON only, no extra text.
"""

def build_user_prompt(host_results: List[Dict[str, str]], nuclei_hint: Optional[str]) -> str:
    lines = [f"K={len(host_results)}"]
    if nuclei_hint:
        lines.append(f"NUCLEI: {nuclei_hint.strip()}")
    lines.append("")
    for res in host_results:
        label = res.get("label")
        if label:
            part = [f"TARGET: {label}", f"HOST: {res['url']}"]
        else:
            part = [f"HOST: {res['url']}"]
        part.append(f"RETURNCODE: {res['rc']}")
        if res.get("stderr"):
            part.append("STDERR:\n" + res["stderr"].strip())
        if res.get("stdout"):
            part.append("STDOUT:\n" + res["stdout"].strip())
        # include one-hop follow target
        if res.get("follow_stdout") or res.get("follow_stderr"):
            part.append("FOLLOW_ONE_STDOUT:\n" + (res.get("follow_stdout","").strip()))
            if res.get("follow_stderr"):
                part.append("FOLLOW_ONE_STDERR:\n" + res["follow_stderr"].strip())
        lines.append("\n".join(part))
    return "\n\n---\n\n".join(lines)

def analyze_chunk_with_openai(client, model: str, host_results: List[Dict[str, str]],
                              nuclei_hint: Optional[str], retries: int = 3,
                              backoff: float = 1.6) -> Tuple[List[str], List[str]]:
    user_prompt = build_user_prompt(host_results, nuclei_hint)
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SIMPLE_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=500,
            )
            txt = resp.choices[0].message.content.strip()
            obj = json.loads(txt)
            notes = obj.get("notes", [])
            sigs  = obj.get("sigs", [])
            if (isinstance(notes, list) and isinstance(sigs, list)
                and len(notes) == len(host_results) and len(sigs) == len(host_results)):
                notes = [(n or "") if isinstance(n, str) else "" for n in notes]
                sigs  = [(s or "").strip() if isinstance(s, str) else "" for s in sigs]
                return notes, sigs
        except Exception:
            time.sleep(backoff ** attempt)
    return [""] * len(host_results), [""] * len(host_results)

# ---------- Grouping across whole row ----------
def group_and_format(target_labels: List[str], notes_all: List[str], sigs_all: List[str], frag_limit: int) -> str:
    """
    Combine hosts with identical 'sig' into concise fragments.
    - Redirect sigs "30x->target" become: "h1, h2 -> target (tech...)" when tech present
    - Non-redirect groups: "h1, h2: <note>"
    Each fragment is truncated to frag_limit chars; fragments joined with " ; ".
    """
    groups: Dict[str, List[int]] = {}
    for i, sig in enumerate(sigs_all):
        groups.setdefault(sig or "__nosig__", []).append(i)

    frags = []
    for sig, idxs in groups.items():
        group_hosts = [target_labels[i] for i in idxs]

        # choose first non-empty note; else fallback
        rep_note = ""
        for i in idxs:
            if notes_all[i]:
                rep_note = notes_all[i]
                break
        if not rep_note:
            rep_note = "No response"
        rep_note = normalize_http_label(rep_note)

        m = re.match(r"3\d\d->([^|]+)", sig) if sig else None
        if m:
            target_host = m.group(1)
            hostlist = abbreviate_hosts(group_hosts, maxlen=60)
            tech = extract_tech_from_note(rep_note)
            if tech:
                frag = f"{hostlist} -> {target_host} ({tech})"
            else:
                frag = f"{hostlist} -> {target_host}"
        else:
            hostlist = abbreviate_hosts(group_hosts, maxlen=60)
            frag = f"{hostlist}: {rep_note}"

        frags.append(safe_trunc(frag, frag_limit))

    return " ; ".join(frags)

# ---------- CSV ----------
BASE_COLS = ["DNS", "IP / Hosting Provider", "Ports", "Nuclei"]
NOTES_COL = "Notes"

def normalize_fieldnames(fieldnames):
    return [fn.strip() if isinstance(fn, str) else fn for fn in (fieldnames or [])]

def ensure_required_fields(fieldnames):
    missing = [col for col in BASE_COLS if col not in fieldnames]
    if missing:
        sys.stderr.write(f"[!] Missing required column(s): {', '.join(missing)}\n")
        sys.exit(1)

# ---------- Main processing ----------
def process_csv(input_path: str, output_path: Optional[str], max_hosts_per_row: int, timeout: int,
                ua: str, max_bytes: int, model: str, show_headers: bool, frag_limit: int,
                chunk_size: int, follow_one: bool, max_ports_per_host: int):
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

    iter_rows = alive_it(rows, title="Curling & LLM grouping") if _HAS_ALIVE else rows
    total = len(rows)
    out_rows = []

    for idx, row in enumerate(iter_rows):
        dns_cell = (row.get("DNS") or "").strip()
        provider_cell = (row.get("IP / Hosting Provider") or "").strip()
        ports_cell = row.get("Ports", "")
        nuclei_hint = (row.get("Nuclei") or "").strip()

        ports = parse_ports_cell(ports_cell)
        port_choices = choose_schemes_and_ports(ports, max_ports_per_host)
        if not port_choices:
            out_rows.append(row)
            if _HAS_ALIVE: iter_rows.text = f"{idx+1}/{total} skip (non-web)"
            continue

        hostnames = split_hosts(dns_cell, max_hosts_per_row)
        if not hostnames:
            ip = extract_ip_from_provider_cell(provider_cell)
            if not ip:
                out_rows.append(row)
                if _HAS_ALIVE: iter_rows.text = f"{idx+1}/{total} skip (no DNS/IP)"
                continue
            hostnames = [ip]

        targets = []
        for hostname in hostnames:
            for scheme, port in port_choices:
                targets.append((hostname, scheme, port, format_target_label(hostname, scheme, port)))
        if not targets:
            out_rows.append(row)
            if _HAS_ALIVE: iter_rows.text = f"{idx+1}/{total} skip (no targets)"
            continue
        target_labels = [t[3] for t in targets]

        if _HAS_ALIVE:
            iter_rows.text = f"{idx+1}/{total} {target_labels[0][:50]}"

        host_results = []
        for hostname, scheme, port, label in targets:
            if _HAS_ALIVE:
                iter_rows.text = f"{idx+1}/{total} curl {label}"
            res = run_curl(hostname, scheme, port, timeout, ua, max_bytes)
            res["label"] = label
            res["host"] = hostname
            res["scheme"] = scheme
            res["port"] = port

            # one-hop follow after 30x to capture tech/meta on destination
            code, loc = parse_status_and_location(res.get("stdout",""))
            if follow_one and code in ("301","302","307","308") and loc:
                if loc.lower().startswith(("http://", "https://")):
                    follow_url = loc
                else:
                    base = f"{scheme}://{hostname}"
                    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
                        base = f"{scheme}://{hostname}:{port}"
                    if loc.startswith("//"):
                        follow_url = f"{scheme}:{loc}"
                    elif loc.startswith("/"):
                        follow_url = base + loc
                    else:
                        follow_url = base.rstrip("/") + "/" + loc
                follow_res = run_curl_url(follow_url, timeout, ua, max_bytes)
                res["follow_stdout"] = follow_res.get("stdout","")
                res["follow_stderr"] = follow_res.get("stderr","")

            host_results.append(res)

        # LLM per-chunk (strict per-host), then group across the row
        notes_all: List[str] = []
        sigs_all:  List[str] = []

        for i in range(0, len(host_results), chunk_size):
            chunk = host_results[i:i+chunk_size]
            notes, sigs = analyze_chunk_with_openai(client, model, chunk, nuclei_hint)

            # Fill blanks with local fallback & minimal sig
            for j in range(len(chunk)):
                if not notes[j]:
                    notes[j] = local_fallback_note(chunk[j]) or "No response"
                if not sigs[j]:
                    stdout = chunk[j].get("stdout", "")
                    mcode = re.search(r"^HTTP/\d\.\d\s+(\d{3})", stdout, re.M)
                    code = mcode.group(1) if mcode else "noresp"
                    if code in ("301","302","307","308"):
                        mloc = re.search(r"^Location:\s*(\S+)", stdout, re.I|re.M)
                        tgt = re.sub(r"^https?://", "", mloc.group(1)).split("/",1)[0] if mloc else ""
                        sigs[j] = f"3xx->{tgt}" if tgt else "3xx"
                    else:
                        sigs[j] = code

            # Heuristic Fortinet detection for ACME Access Only banner
            for j in range(len(chunk)):
                res = chunk[j]
                blob = " ".join(
                    filter(None,
                        [res.get("stdout"), res.get("stderr"), res.get("follow_stdout"), res.get("follow_stderr"), notes[j]])
                ).lower()
                if "acme access only" in blob:
                    existing_note = notes[j] or ""
                    if "fortinet" not in existing_note.lower():
                        prefix = "Fortinet FortiGate VPN portal (ACME Access Only banner). " if existing_note else "Fortinet FortiGate VPN portal (ACME Access Only banner)."
                        notes[j] = prefix + existing_note
                    sig = sigs[j] or ""
                    if "fortinet" not in sig.lower():
                        sigs[j] = f"{sig}|fortinet" if sig else "fortinet"

            notes = [normalize_http_label(n) for n in notes]
            notes_all.extend(notes)
            sigs_all.extend(sigs)

        combined = group_and_format(target_labels, notes_all, sigs_all, frag_limit=frag_limit)
        row["Notes"] = combined
        out_rows.append(row)

    write_path = output_path or input_path
    with open(write_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"[+] Wrote: {write_path}")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description="Fill the Notes column (from new-recon.py CSV) using curl + LLM per-host analysis with one-hop follow and local grouping."
    )
    parser.add_argument("input_csv", help="CSV from new-recon.py (columns: DNS, IP / Hosting Provider, Ports, Nuclei, Notes)")
    parser.add_argument("-o", "--output-csv", help="Optional output CSV path. If omitted, overwrite input CSV.")
    parser.add_argument("--max-hosts-per-row", type=int, default=60, help="Max hostnames to parse from DNS cell (default 60)")
    parser.add_argument("--timeout", type=int, default=15, help="curl timeout seconds (default 15)")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (compatible; ReconBot/1.0)", help="curl User-Agent")
    parser.add_argument("--max-bytes", type=int, default=4096, help="Truncate curl stdout to this many bytes (default 4096)")
    parser.add_argument("--model", default="gpt-4.1", help="OpenAI model (e.g., gpt-4.1, gpt-4o)")
    parser.add_argument("--show-headers", action="store_true", help="Print detected CSV header names")
    parser.add_argument("--max-fragment-len", type=int, default=140, help="Max characters per Notes fragment (default 140)")
    parser.add_argument("--chunk-size", type=int, default=3, help="Hosts per LLM prompt chunk (default 3)")
    # follow-one enabled by default; provide opt-out switch
    parser.add_argument("--no-follow-one", dest="follow_one", action="store_false", help="Disable one-hop follow after 30x")
    parser.set_defaults(follow_one=True)
    parser.add_argument("--max-ports-per-host", type=int, default=5, help="Max HTTP-like ports to curl per host (default 5)")
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
        frag_limit=args.max_fragment_len,
        chunk_size=args.chunk_size,
        follow_one=args.follow_one,
        max_ports_per_host=args.max_ports_per_host,
    )

if __name__ == "__main__":
    main()
