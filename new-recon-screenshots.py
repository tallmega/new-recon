#!/usr/bin/env python3
"""
Generate EyeWitness screenshots from a new-recon + ai-notes CSV and render an HTML report.

Workflow:
  1. Parse the CSV (columns: DNS, IP / Hosting Provider, Ports, Nuclei, Notes)
  2. Select HTTP-like host:port combos that look interesting (non-empty Notes/Nuclei)
  3. Write them to an EyeWitness targets file
  4. Optionally run EyeWitness automatically
  5. Build an HTML table (and optional CSV) with screenshot links for documentation
"""

import argparse, csv, html, json, os, re, shutil, subprocess, sys
from urllib.parse import urlparse

try:
    from PIL import Image
    _HAS_PIL=True
except ImportError:
    _HAS_PIL=False
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple, Set

_HAS_ALIVE=False
try:
    from alive_progress import alive_it
    _HAS_ALIVE=True
except Exception:
    _HAS_ALIVE=False

HTTP_PORTS={80,81,3000,5000,7001,7080,7081,7443,8000,8008,8080,8081,8088,
            8181,8443,8448,8880,8888,9000,9080,9090,9200,9443,10000,10443,
            11080,12000,12345,16080,18080,443,4443,4444,451,591,593,8320}
PRIMARY_HTTP_PORTS={80,443}
ALT_HTTP_PORTS={8080,8443,8880,8008,8015}

IMAGE_EXTS=(".png",".jpg",".jpeg",".webp",".bmp",".gif")
BASE_COLS=["DNS","IP / Hosting Provider","Ports","Nuclei"]
NOTES_COL="Notes"
IPV4_RE=re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6_RE=re.compile(r"\b([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

@dataclass(frozen=True)
class Target:
    host:str
    port:int
    scheme:str
    path:str="/"
    status:Optional[int]=None

def normalize_fieldnames(fieldnames:Sequence[str]) -> List[str]:
    return [fn.strip() if isinstance(fn,str) else fn for fn in (fieldnames or [])]

def ensure_required_fields(fieldnames:Sequence[str]) -> None:
    missing=[col for col in BASE_COLS if col not in fieldnames]
    if missing:
        sys.stderr.write(f"[!] Missing required column(s): {', '.join(missing)}\n")
        sys.exit(1)

def split_hosts(cell:str,max_hosts:int) -> List[str]:
    if not cell:
        return []
    raw=re.split(r"[,\s;]+",cell.strip())
    hosts=[]
    seen=set()
    for h in raw:
        if not h:
            continue
        if h not in seen:
            seen.add(h)
            hosts.append(h)
        if len(hosts)>=max_hosts:
            break
    return hosts

def extract_ip(cell:str) -> Optional[str]:
    if not cell:
        return None
    m4=IPV4_RE.search(cell)
    if m4:
        return m4.group(0)
    m6=IPV6_RE.search(cell)
    if m6:
        return m6.group(0)
    return None

def parse_ports_cell(cell:str) -> List[int]:
    if not cell:
        return []
    cell=cell.strip()
    if not cell or cell.lower() in {"none","n/a"}:
        return []
    ports=[]
    for token in cell.split(","):
        token=token.strip()
        m=re.search(r"tcp/(\d+)",token,re.IGNORECASE)
        if not m:
            continue
        try:
            ports.append(int(m.group(1)))
        except ValueError:
            continue
    return ports

def select_http_ports(ports:List[int]) -> List[int]:
    return sorted({p for p in ports if p in HTTP_PORTS})

def port_scheme(port:int) -> str:
    return "https" if port in {443,4443,5443,6443,7443,8443,9443,10443} else "http"

def normalize_path(path:str) -> str:
    if not path:
        return "/"
    if not path.startswith("/"):
        path=f"/{path}"
    # collapse multiple slashes
    while "//" in path:
        path=path.replace("//","/")
    return path or "/"

def path_variants(path:str) -> List[str]:
    base=normalize_path(path)
    variants=[base]
    if base!="/" and base.endswith("/"):
        variants.append(base.rstrip("/"))
    elif base!="/":
        variants.append(f"{base}/")
    return list(dict.fromkeys([p if p else "/" for p in variants]))

def default_port_for_scheme(scheme:str) -> int:
    return 443 if scheme=="https" else 80

def _mapping_matches_target(value:Dict[str,str],target:Target) -> bool:
    url=value.get("url") or ""
    try:
        parsed=urlparse(url)
    except Exception:
        return False
    host=canonical_host(parsed.hostname or "")
    if host and host!=canonical_host(target.host):
        return False
    scheme=parsed.scheme or target.scheme
    port=parsed.port or default_port_for_scheme(scheme)
    if port!=target.port:
        return False
    path=normalize_path(parsed.path or "/")
    return path==normalize_path(target.path or "/")

def target_to_url(t:Target) -> str:
    host=t.host.strip()
    if ":" in host and not host.startswith("["):
        host=f"[{host}]"
    default_port=default_port_for_scheme(t.scheme)
    port_part=f":{t.port}" if t.port and t.port!=default_port else ""
    path=normalize_path(t.path or "/")
    return f"{t.scheme}://{host}{port_part}{path}"

def is_interesting_row(nuclei:str,notes:str) -> bool:
    nuclei=(nuclei or "").strip()
    notes=(notes or "").strip()
    if nuclei:
        return True
    if not notes:
        return False
    lower=notes.lower()
    if lower in {"no response","n/a","none"}:
        return False
    return True

URL_EXTRACT_RE=re.compile(r"https?://[^\s;,]+",re.IGNORECASE)
FUZZ_ENTRY_RE=re.compile(r"^(?:Fuzz(?:ing\s+Results\s*-\s*)?)\s*([^:]+):\s*(.+)$",re.IGNORECASE)
REDIRECT_RE=re.compile(r"redirect\s*->\s*([^;|]+)",re.IGNORECASE)
OK_RE=re.compile(r"200\s*->\s*([^;|]+)",re.IGNORECASE)
STATUS_SUFFIX_RE=re.compile(r"\s*\[([0-9]{3})\]\s*$")
NOTE_REDIRECT_RE=re.compile(r"(https?://[^\s;,]+)\s*->\s*([^;|]+)")
FILE_EXT_HINTS={"php","asp","aspx","jsp","html","htm","cgi","pl","cfm","php5","php7","jspx","do","action"}
FUZZ_NO_MATCH_RE=re.compile(r"Fuzzing Results\s*-\s*(?:[^:]+:\s*)?no\s+ffuf\s+matches",re.IGNORECASE)

def _split_note_fragments(notes:str) -> List[str]:
    frags=[]
    for part in notes.split(";"):
        part=part.strip()
        if not part:
            continue
        subparts=[p.strip() for p in part.split("|") if p.strip()]
        if subparts:
            frags.extend(subparts)
        else:
            frags.append(part)
    return frags

def sanitize_fuzzing_text(text:str) -> str:
    if not text:
        return ""
    return FUZZ_NO_MATCH_RE.sub("Fuzzing Results - no matches",text)

def _normalize_url_for_match(url:str) -> str:
    return url.lower().rstrip("/")

def find_fragment_index(fragments:List[str],host_hint:str,path_hint:str,scheme_hint:str="",port_hint:Optional[int]=None,label_hint:str="") -> Optional[int]:
    host_hint=(host_hint or "").lower()
    path_hint=normalize_path(path_hint or "/").lower()
    scheme_hint=(scheme_hint or "").lower()
    label_lower=_normalize_url_for_match(label_hint or "")
    target_url=""
    if scheme_hint and host_hint:
        base=f"{scheme_hint}://{host_hint}"
        if port_hint and port_hint!=default_port_for_scheme(scheme_hint):
            target_url=f"{base}:{port_hint}{path_hint}"
        else:
            target_url=f"{base}{path_hint}"
    url_variants={label_lower.rstrip("/")} if label_lower else set()
    if target_url:
        url_variants.add(_normalize_url_for_match(target_url))
    host_path=f"{host_hint}{path_hint}"
    for idx,frag in enumerate(fragments):
        lower=frag.lower()
        urls=[_normalize_url_for_match(m.group(0)) for m in URL_EXTRACT_RE.finditer(lower)]
        if url_variants & set(urls):
            return idx
        if host_hint and f"{scheme_hint}://{host_hint}" in lower:
            if port_hint and port_hint!=default_port_for_scheme(scheme_hint):
                if f"{scheme_hint}://{host_hint}:{port_hint}" in lower:
                    return idx
            else:
                return idx
        if host_path.strip("/") and host_path in lower:
            return idx
        if host_hint and host_hint in lower and not urls:
            return idx
    return None

def _parse_label_url(label:str) -> Optional[Tuple[str,str,int]]:
    label=label.strip()
    if not label:
        return None
    if label.startswith(("http://","https://")):
        try:
            parsed=urlparse(label)
            host=parsed.hostname
            if not host:
                return None
            scheme=parsed.scheme or "https"
            port=parsed.port or (443 if scheme=="https" else 80)
            return scheme,host,port
        except Exception:
            return None
    host=label
    port=None
    if host.startswith("[") and "]" in host:
        h,rest=host.split("]",1)
        host=h[1:]
        if rest.startswith(":"):
            try: port=int(rest[1:])
            except ValueError: port=None
    elif ":" in host:
        base,maybe_port=host.rsplit(":",1)
        if maybe_port.isdigit():
            host=base
            try: port=int(maybe_port)
            except ValueError: port=None
    host=host.strip().strip("[]")
    if not host:
        return None
    if port is None:
        port=443
    scheme="https" if port==443 else ("http" if port==80 else "https")
    return scheme,host,port

def _build_url(scheme:str,host:str,port:Optional[int],path:str="/") -> str:
    scheme=(scheme or "https").lower()
    host=host.strip()
    if ":" in host and not host.startswith("["):
        host=f"[{host}]"
    default_port=443 if scheme=="https" else 80
    port_part=f":{port}" if port and port!=default_port else ""
    norm_path=normalize_path(path)
    return f"{scheme}://{host}{port_part}{norm_path}"

def _strip_status(value:str) -> Tuple[str,Optional[int]]:
    value=value.strip()
    m=STATUS_SUFFIX_RE.search(value)
    if m:
        try:
            status=int(m.group(1))
        except ValueError:
            status=None
        value=value[:m.start()].rstrip()
        return value,status
    return value,None

def _clean_destination_token(value:str) -> str:
    value=value.strip()
    # remove trailing parenthetical annotations like "(Apache)" or "(nginx)"
    value=re.sub(r"\s*\([^)]*\)\s*$","",value)
    return value.strip()

def _segment_is_domain(segment:str) -> bool:
    seg=segment.strip().lower()
    if not seg:
        return False
    # treat file-like segments as paths, not domains
    tail=seg.split(".")[-1]
    if tail in FILE_EXT_HINTS:
        return False
    # simple domain heuristic
    if seg.count(".")>=1 and all(re.match(r"[a-z0-9-]+",part or "") for part in seg.split(".")):
        return True
    return False

def _resolve_destination(value:str,base:Tuple[str,str,int],prefer_relative:bool=False) -> Optional[str]:
    if not value:
        return None
    value=value.strip()
    # strip trailing section separators before annotation removal
    value=re.split(r"[;|]",value,maxsplit=1)[0].strip()
    value=re.split(r"\s\+\d+\s+more",value,maxsplit=1)[0].strip()
    value=value.strip(",")
    # drop trailing parenthetical descriptors
    value=_clean_destination_token(value)
    # drop residual trailing comma-separated descriptors
    value=value.split(",")[0].strip()
    # drop trailing space-delimited annotations
    if " " in value and not value.startswith(("http://","https://","//")):
        value=value.split(" ",1)[0].strip()
    if not value:
        return None
    if value.startswith(("http://","https://")):
        token=value.split()[0].strip()
        return token
    if value.startswith("//"):
        return f"{base[0]}:{value}"
    if value.lower() in {"http","https"}:
        return _build_url(value.lower(),base[1],base[2],"/")
    if value.startswith("/"):
        return _build_url(base[0],base[1],base[2],value)
    segment=value.split("/",1)[0]
    if _segment_is_domain(segment):
        host,value_path=(value.split("/",1)+[""])[:2]
        value_path=f"/{value_path}" if value_path else "/"
        return _build_url("https",host,None,value_path)
    # treat remaining token as relative path/file
    rel_path=value if value.startswith("/") else f"/{value.lstrip('/')}"
    return _build_url(base[0],base[1],base[2],rel_path if rel_path else "/")

def extract_fuzz_targets(fragments:List[str],known_hosts:Set[str]) -> List[Tuple[Target,int]]:
    urls=[]
    for idx,frag in enumerate(fragments):
        m=FUZZ_ENTRY_RE.match(frag)
        if not m:
            continue
        label=m.group(1).strip()
        rest=m.group(2)
        base=_parse_label_url(label)
        if not base:
            continue
        scheme,host,port=base
        redirect_val=None
        redirect_status=None
        ok_val=None
        ok_status=None
        m_red=REDIRECT_RE.search(rest)
        if m_red:
            raw_red=m_red.group(1).split(",")[0].strip()
            redirect_val,redirect_status=_strip_status(raw_red)
        m_ok=OK_RE.search(rest)
        if m_ok:
            raw_ok=m_ok.group(1).split(",")[0].strip()
            ok_val,ok_status=_strip_status(raw_ok)
        candidate=None
        candidate_status=None
        if redirect_val:
            candidate=_resolve_destination(redirect_val,base)
            candidate_status=redirect_status
        elif ok_val:
            candidate=_resolve_destination(ok_val,base,prefer_relative=True)
            candidate_status=ok_status
        if not candidate:
            continue
        try:
            parsed=urlparse(candidate)
            chost=canonical_host(parsed.hostname or "")
            if known_hosts and chost not in known_hosts:
                continue
            url_scheme=parsed.scheme or scheme
            url_host=parsed.hostname or host
            url_port=parsed.port or (443 if url_scheme=="https" else 80)
            url_path=parsed.path or "/"
            urls.append((Target(host=url_host,port=url_port,scheme=url_scheme,path=url_path,status=candidate_status),idx))
        except Exception:
            continue
    return urls

def extract_redirect_targets(fragments:List[str],known_hosts:Set[str]) -> List[Tuple[Target,int]]:
    urls=[]
    for idx,frag in enumerate(fragments):
        for match in NOTE_REDIRECT_RE.finditer(frag):
            src=match.group(1).strip()
            dest=match.group(2).split(",")[0].strip()
            base=_parse_label_url(src)
            if not base:
                continue
            scheme,host,port=base
            dest_url=_resolve_destination(dest,base)
            if not dest_url:
                continue
            try:
                parsed=urlparse(dest_url)
                chost=canonical_host(parsed.hostname or "")
                if known_hosts and chost not in known_hosts:
                    continue
                url_scheme=parsed.scheme or scheme
                url_host=parsed.hostname or host
                url_port=parsed.port or (443 if url_scheme=="https" else 80)
                url_path=parsed.path or "/"
                urls.append((Target(host=url_host,port=url_port,scheme=url_scheme,path=url_path),idx))
            except Exception:
                continue
    return urls

def build_targets(rows:List[Dict[str,str]],max_hosts:int,only_interesting:bool) -> Tuple[List[List[Dict[str,object]]],List[Target]]:
    per_row=[]
    aggregate=[]
    aggregate_seen=set()
    for row in rows:
        hosts=split_hosts(row.get("DNS",""),max_hosts)
        provider_ip=extract_ip(row.get("IP / Hosting Provider",""))
        if not hosts and provider_ip:
            hosts=[provider_ip]
        canonical_hosts={canonical_host(h) for h in hosts if h}
        skip_www_hosts={h for h in canonical_hosts if h.startswith("www.") and h[4:] in canonical_hosts}
        ports=parse_ports_cell(row.get("Ports",""))
        http_ports=select_http_ports(ports)
        notes=row.get(NOTES_COL,"") or ""
        fragments=_split_note_fragments(notes)
        if only_interesting and not is_interesting_row(row.get("Nuclei",""),notes):
            per_row.append([])
            continue
        known_hosts={canonical_host(h) for h in hosts}
        if provider_ip:
            known_hosts.add(canonical_host(provider_ip))
        row_entries=[]
        hosts_with_primary_http=set()

        def add_entry(target:Target,fragment_idx:Optional[int],source:str="port")->bool:
            canon=canonical_host(target.host)
            if target.port in ALT_HTTP_PORTS and canon in hosts_with_primary_http:
                return False
            row_entries.append({"target":target,"fragment":fragment_idx})
            key=(canon,target.scheme,target.port,normalize_path(target.path))
            if key not in aggregate_seen:
                aggregate.append(target)
                aggregate_seen.add(key)
            return True

        if hosts and http_ports:
            sorted_ports=sorted(http_ports,key=lambda p:(0 if p in PRIMARY_HTTP_PORTS else 1,p))
            for host in hosts:
                if not host:
                    continue
                canon_host=canonical_host(host)
                if canon_host in skip_www_hosts:
                    continue
                for port in sorted_ports:
                    if port in ALT_HTTP_PORTS and canon_host in hosts_with_primary_http:
                        continue
                    scheme=port_scheme(port)
                    target=Target(host=host,port=port,scheme=scheme,path="/")
                    frag_idx=find_fragment_index(
                        fragments,
                        canon_host,
                        "/",
                        scheme,
                        port,
                        target_to_url(target)
                    )
                    added=add_entry(target,frag_idx,"port")
                    if added and port in PRIMARY_HTTP_PORTS:
                        hosts_with_primary_http.add(canon_host)

        fuzz_targets=extract_fuzz_targets(fragments,known_hosts)
        for tgt,idx in fuzz_targets:
            add_entry(tgt,idx,"fuzz")

        redirect_targets=extract_redirect_targets(fragments,known_hosts)
        for tgt,idx in redirect_targets:
            add_entry(tgt,idx,"redirect")

        per_row.append(row_entries)
    return per_row,aggregate

def ensure_dir(path:str) -> None:
    os.makedirs(path,exist_ok=True)

def write_targets_file(targets:Sequence[Target],path:str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path,"w",encoding="utf-8") as f:
        for tgt in targets:
            f.write(target_to_url(tgt)+"\n")

def _candidate_roots(root_hint:Optional[str]) -> List[str]:
    roots=[]
    if root_hint:
        roots.append(os.path.expanduser(root_hint))
    cwd=os.getcwd()
    script_dir=os.path.dirname(os.path.abspath(__file__))
    roots.extend([
        cwd,
        script_dir,
        os.path.dirname(script_dir),
        os.path.expanduser("~/EyeWitness"),
        os.path.expanduser("~/eyewitness"),
        os.path.expanduser("~/tools/EyeWitness"),
    ])
    cleaned=[]
    seen=set()
    for r in roots:
        if not r:
            continue
        norm=os.path.normpath(r)
        if norm in seen:
            continue
        seen.add(norm)
        cleaned.append(norm)
    return cleaned

def resolve_eyewitness_python(explicit:Optional[str],root_hint:Optional[str]) -> Optional[str]:
    if explicit:
        expanded=os.path.expanduser(explicit)
        if os.path.isfile(expanded) or shutil.which(expanded):
            return expanded
    for root in _candidate_roots(root_hint):
        candidates=[
            os.path.join(root,"eyewitness-venv","bin","python"),
            os.path.join(root,"eyewitness-venv","Scripts","python.exe"),
            os.path.join(root,"venv","bin","python"),
            os.path.join(root,"venv","Scripts","python.exe"),
            os.path.join(root,"bin","python"),
            os.path.join(root,"Scripts","python.exe"),
        ]
        for cand in candidates:
            if os.path.isfile(cand):
                return cand
    for fallback in ("python3","python"):
        resolved=shutil.which(fallback)
        if resolved:
            return resolved
    return None

def resolve_eyewitness_script(explicit:Optional[str],root_hint:Optional[str]) -> Optional[str]:
    if explicit:
        expanded=os.path.expanduser(explicit)
        return expanded if os.path.isfile(expanded) else None
    for root in _candidate_roots(root_hint):
        candidates=[
            os.path.join(root,"Python","EyeWitness.py"),
            os.path.join(root,"EyeWitness.py"),
        ]
        for cand in candidates:
            if os.path.isfile(cand):
                return cand
    return None

def build_default_extra(extra: Optional[List[str]]) -> List[str]:
    result=list(extra or [])
    ua_present=any(arg in ("--user-agent","-ua","-uA") for arg in result)
    if not ua_present:
        result.extend(["--user-agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"])
    return result

def run_eyewitness(python_bin:str,script:str,targets_file:str,out_dir:str,extra:List[str],timeout:int,workdir:Optional[str]) -> bool:
    base_args=["--web","--timeout",str(timeout),"--no-prompt","-f",targets_file,"-d",out_dir]
    combined_args=base_args+extra
    commands=[]
    if python_bin:
        commands.append((python_bin,[python_bin,script]+combined_args))
    commands.append(("system",["python3",script]+combined_args))
    commands.append(("system",["python",script]+combined_args))
    for label,argv in commands:
        env=os.environ.copy()
        if label != "system" and python_bin:
            venv_dir=os.path.dirname(os.path.dirname(python_bin))
            if os.path.exists(os.path.join(venv_dir,"bin","activate")) or os.path.exists(os.path.join(venv_dir,"Scripts","activate.bat")):
                env["VIRTUAL_ENV"]=venv_dir
                bin_dir=os.path.dirname(python_bin)
                env["PATH"]=bin_dir+os.pathsep+env.get("PATH","")
        cwd=workdir or os.path.dirname(script)
        try:
            subprocess.run(argv,check=True,env=env,cwd=cwd)
            return True
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError as exc:
            print(f"[!] EyeWitness ({label}) exited with {exc.returncode}")
    return False

def build_screenshot_index(base_dir:str) -> List[str]:
    shots=[]
    if not os.path.isdir(base_dir):
        return shots
    for root,_,files in os.walk(base_dir):
        for fn in files:
            if fn.lower().endswith(IMAGE_EXTS):
                shots.append(os.path.join(root,fn))
    return shots

def generate_thumbnails(shots:List[str],base_dir:str,max_width:int=320) -> Dict[str,str]:
    thumbs={}
    if not shots:
        return thumbs
    thumb_dir=os.path.join(base_dir,"thumbs")
    os.makedirs(thumb_dir,exist_ok=True)
    for original in shots:
        try:
            name=os.path.basename(original)
            thumb_path=os.path.join(thumb_dir,name)
            if os.path.isfile(thumb_path):
                thumbs[original]=thumb_path
                continue
            if not _HAS_PIL:
                shutil.copyfile(original,thumb_path)
                thumbs[original]=thumb_path
                continue
            with Image.open(original) as img:
                width, height = img.size
                if width <= max_width:
                    img.save(thumb_path)
                else:
                    ratio=max_width/float(width)
                    new_size=(max_width,int(height*ratio))
                    img.resize(new_size,Image.LANCZOS).save(thumb_path)
            thumbs[original]=thumb_path
        except Exception:
            continue
    return thumbs

def canonical_host(host:str) -> str:
    return (host or "").strip().lower().rstrip(".")

def _merge_mapping_entry(mapping:Dict[Tuple[str,int,str],Dict[str,str]],key:Tuple[str,int,str],data:Dict[str,str]) -> None:
    if not data:
        return
    existing=mapping.get(key)
    if not existing:
        mapping[key]=data.copy()
        return
    if data.get("path") and not existing.get("path"):
        existing["path"]=data["path"]
    if data.get("url"):
        existing["url"]=data["url"]
    if data.get("status"):
        existing["status"]=data["status"]
    if data.get("title"):
        existing["title"]=data["title"]

def add_mapping_entry(mapping:Dict[Tuple[str,int,str],Dict[str,str]],url:str,shot_path:Optional[str]=None,status:Optional[str]=None,title:Optional[str]=None) -> None:
    if not url:
        return
    try:
        parsed=urlparse(url)
    except Exception:
        return
    host=canonical_host(parsed.hostname or "")
    if not host:
        return
    scheme=parsed.scheme or "https"
    port=parsed.port or default_port_for_scheme(scheme)
    path=normalize_path(parsed.path or "/")
    full_url=_build_url(scheme,host,port,path)
    value={"path":shot_path or "","url":full_url,"status":status or "","title":title or ""}
    for variant in path_variants(path):
        _merge_mapping_entry(mapping,(host,port,variant),value)

def load_eyewitness_mapping(base_dir:str) -> Dict[Tuple[str,int,str],Dict[str,str]]:
    mapping={}
    report=os.path.join(base_dir,"report.json")
    legacy=os.path.join(base_dir,"results.json")
    candidates=[path for path in (report,legacy) if os.path.isfile(path)]
    for path in candidates:
        try:
            with open(path,"r",encoding="utf-8") as f:
                data=json.load(f)
            entries=[]
            if isinstance(data,dict):
                for key in ("data","results","entries"):
                    if key in data and isinstance(data[key],list):
                        entries=data[key]
                        break
                if not entries and isinstance(data.get("screenshots"),list):
                    entries=data["screenshots"]
            elif isinstance(data,list):
                entries=data
            for entry in entries:
                screenshot=(entry.get("screenshot") or entry.get("screenshot_path") or entry.get("image"))
                if not screenshot:
                    continue
                shot_path=os.path.join(base_dir,screenshot) if not os.path.isabs(screenshot) else screenshot
                url_candidates=[]
                for key in ("url","final_url","input_url","target_url","requested_url"):
                    val=entry.get(key)
                    if val:
                        url_candidates.append(val)
                for url in url_candidates:
                    add_mapping_entry(mapping,url,shot_path,entry.get("status") or entry.get("Status"),entry.get("title") or entry.get("Title"))
        except Exception:
            continue
    csv_path=os.path.join(base_dir,"urls.csv")
    if os.path.isfile(csv_path):
        try:
            with open(csv_path,newline="",encoding="utf-8") as f:
                reader=csv.DictReader(f)
                for row in reader:
                    screenshot=row.get("Screenshot Path") or row.get("Screenshot") or row.get("screenshot")
                    if not screenshot:
                        continue
                    shot_path=os.path.join(base_dir,screenshot) if not os.path.isabs(screenshot) else screenshot
                    url_candidates=[]
                    for key in ("URL","Url","url","Final URL","FinalUrl","final_url","Input URL","InputUrl","input_url"):
                        val=row.get(key)
                        if val:
                            url_candidates.append(val)
                    for url in url_candidates:
                        add_mapping_entry(mapping,url,shot_path,row.get("Status") or row.get("status"),row.get("Title") or row.get("title"))
        except Exception:
            pass
    requests_csv=os.path.join(base_dir,"Requests.csv")
    if os.path.isfile(requests_csv):
        try:
            with open(requests_csv,newline="",encoding="utf-8") as f:
                reader=csv.DictReader(f)
                for row in reader:
                    url=row.get("URL") or ""
                    shot=row.get("Screenshot Path") or ""
                    if not url:
                        continue
                    shot_path=shot if shot and os.path.isabs(shot) else (os.path.join(base_dir,shot.lstrip("/")) if shot else "")
                    add_mapping_entry(
                        mapping,
                        url,
                        shot_path or "",
                        row.get("Request Status") or row.get("Status"),
                        row.get("Title") or row.get("Category")
                    )
        except Exception:
            pass
    return mapping

def sanitize(s:str) -> str:
    return re.sub(r"[^0-9A-Za-z]+","_",s)

def locate_screenshot(target:Target,mapping:Dict[Tuple[str,int,str],Dict[str,str]],shots:List[str]) -> Optional[Dict[str,str]]:
    host_key=canonical_host(target.host)
    path=normalize_path(target.path)
    default_port=default_port_for_scheme(target.scheme)
    key=(host_key,target.port,path)
    val=mapping.get(key)
    if val and _mapping_matches_target(val,target):
        path_val=val.get("path") or ""
        if path_val and os.path.isfile(path_val):
            return val
        if val.get("status"):
            return val
    # fallback to same path but default port
    if target.port!=default_port:
        key=(host_key,default_port,path)
        val=mapping.get(key)
        if val and _mapping_matches_target(val,target):
            path_val=val.get("path") or ""
            if path_val and os.path.isfile(path_val):
                return val
            if val.get("status"):
                return val
    # final fallback: root mapping per port (only if target path is root)
    if normalize_path(target.path or "/")=="/":
        root_key=(host_key,target.port,"/")
        val=mapping.get(root_key)
        if val and _mapping_matches_target(val,target):
            path_val=val.get("path") or ""
            if path_val and os.path.isfile(path_val):
                return val
            if val.get("status"):
                return val
    return None

def sanitize_filename(label:str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+","_",label)

def capture_custom_screenshot(chrome_bin:str,url:str,out_dir:str,port:int) -> Optional[str]:
    if not chrome_bin:
        return None
    os.makedirs(out_dir,exist_ok=True)
    fname=sanitize_filename(f"{url}_{port}")[:120]
    out_path=os.path.join(out_dir,f"{fname}.png")
    cmd=[
        chrome_bin,
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        "--ignore-certificate-errors",
        "--allow-running-insecure-content",
        "--disable-web-security",
        "--log-level=2",
        "--window-size=1366,768",
        f"--screenshot={out_path}",
        url,
    ]
    try:
        subprocess.run(cmd,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
    except Exception:
        return None
    return out_path if os.path.isfile(out_path) else None

def to_windows_path(path:str) -> Optional[str]:
    distro=os.environ.get("WSL_DISTRO_NAME")
    if not distro:
        return None
    rel=os.path.relpath(os.path.abspath(path),"/")
    return f"\\\\wsl$\\{distro}\\{rel.replace('/', '\\')}"


def update_rows(rows:List[Dict[str,str]],per_row_targets:List[List[Dict[str,object]]],mapping:Dict[Tuple[str,int,str],Dict[str,str]],shots:List[str],thumbs:Dict[str,str],custom_capture_dir:str,chrome_bin:Optional[str]) -> List[Dict[str,str]]:
    updated=[]
    for row,row_targets in zip(rows,per_row_targets):
        new_row={
            "DNS":row.get("DNS",""),
            "IP / Hosting Provider":row.get("IP / Hosting Provider",""),
            "Ports":row.get("Ports",""),
            "notes_text":row.get("Notes","") or ""
        }
        fragments_summary=[]
        note_fragments=_split_note_fragments(new_row["notes_text"])
        fragment_map={i:[] for i in range(len(note_fragments))}
        leftovers=[]

        for info in row_targets:
            tgt:Target=info["target"]  # type: ignore
            frag_idx=info.get("fragment")
            shot_info=locate_screenshot(tgt,mapping,shots) or {}
            resolved_url=shot_info.get("url") or target_to_url(tgt)
            label_display=resolved_url
            if tgt.status:
                label_display=f"{label_display} [{tgt.status}]"
            shot_path=shot_info.get("path") or ""
            entry_dict={
                "label":label_display,
                "path":shot_path,
                "thumb":thumbs.get(shot_path,shot_path) if shot_path else "",
                "status":(shot_info.get("status") or "").strip(),
                "title":(shot_info.get("title") or "").strip(),
            }
            entry_dict["host_hint"]=canonical_host(tgt.host)
            entry_dict["path_hint"]=normalize_path(tgt.path or "/")
            entry_dict["scheme_hint"]=tgt.scheme
            entry_dict["port_hint"]=tgt.port
            # Determine summary text
            needs_custom=False
            title_lower=entry_dict["title"].lower()
            if title_lower.startswith("!error") or (not shot_path):
                needs_custom=True
            if needs_custom and chrome_bin:
                custom_path=capture_custom_screenshot(chrome_bin,resolved_url,custom_capture_dir,tgt.port)
                if custom_path:
                    shot_path=custom_path
                    entry_dict["path"]=custom_path
                    entry_dict["thumb"]=custom_path
                    entry_dict["status"]="Headless capture"
                    entry_dict["pending"]=False
            if shot_path:
                fragments_summary.append(f"{label_display} -> {shot_path}")
                entry_dict["pending"]=False
            elif entry_dict["status"]:
                fragments_summary.append(f"{label_display} -> {entry_dict['status']}")
                entry_dict["pending"]=False
            else:
                fragments_summary.append(f"{label_display} -> (pending)")
                entry_dict["pending"]=True
            assigned=False
            candidate_indices=[]
            if isinstance(frag_idx,int):
                candidate_indices.append(frag_idx)
            candidate_indices.append(find_fragment_index(
                note_fragments,
                entry_dict["host_hint"],
                entry_dict["path_hint"],
                entry_dict["scheme_hint"],
                entry_dict["port_hint"],
                entry_dict["label"]
            ))
            for idx in candidate_indices:
                if isinstance(idx,int) and idx in fragment_map:
                    fragment_map[idx].append(entry_dict)
                    assigned=True
                    break
            if not assigned:
                leftovers.append(entry_dict)

        new_row["Screenshot"]=" ; ".join(fragments_summary)
        new_row["_note_fragments"]=note_fragments
        new_row["_fragment_shots"]=fragment_map
        new_row["_extra_shots"]=leftovers
        new_row["_targets"]=row_targets
        updated.append(new_row)
    return updated

def write_csv_output(rows:List[Dict[str,str]],path:str) -> None:
    fieldnames=["DNS","IP / Hosting Provider","Ports","Screenshot"]
    with open(path,"w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            row_copy={k:row.get(k,"") for k in fieldnames}
            writer.writerow(row_copy)
    print(f"[+] Wrote: {path}")

def render_shot_block(entry:Dict[str,str],base:str,dns:str,f) -> None:
    thumb_path=entry.get("thumb") or entry.get("path")
    if not thumb_path or not os.path.exists(thumb_path):
        return
    label_text=entry.get("label","")
    f.write("<div class=\"shot-block\">")
    if label_text:
        f.write(f"<div class=\"shot-label\">{html.escape(label_text)}</div>")
    rel=os.path.relpath(thumb_path,base)
    rel_html=html.escape(rel)
    f.write(f"<img src=\"{rel_html}\" alt=\"{dns}\" style=\"width:2in;height:auto;\" width=\"192\">")
    f.write("</div>")

def write_html_output(rows:List[Dict[str,str]],path:str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    base=os.path.dirname(os.path.abspath(path)) or "."
    with open(path,"w",encoding="utf-8") as f:
        f.write("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
        f.write(
            "<style>"
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
            "</style>\n"
        )
        f.write("</head>\n<body>\n")
        f.write("<table>\n<thead><tr><th>FQDN</th><th class=\"col-ip\">First Resolved IP</th><th class=\"col-port\">Ports</th><th>Notes and Screenshots</th></tr></thead>\n<tbody>\n")
        for row in rows:
            dns=html.escape(row.get("DNS",""))
            resolved_ip=extract_ip(row.get("IP / Hosting Provider","")) or row.get("IP / Hosting Provider","")
            ip=html.escape(resolved_ip)
            ports=html.escape(row.get("Ports",""))
            note_text=row.get("notes_text","").strip()
            f.write("<tr>")
            f.write(f"<td>{dns}</td><td class=\"col-ip\">{ip}</td><td class=\"col-port\">{ports}</td>")
            shots=row.get("_targets") or []
            if not shots:
                if note_text:
                    cleaned=sanitize_fuzzing_text(note_text)
                    f.write(f"<td><div class=\"note-text\">{html.escape(cleaned)}</div></td>")
                else:
                    f.write("<td></td>")
            else:
                f.write("<td>")
                note_frags=row.get("_note_fragments") or []
                frag_map=row.get("_fragment_shots") or {}
                extras=row.get("_extra_shots") or []
                if note_frags:
                    for idx,frag in enumerate(note_frags):
                        display_frag=sanitize_fuzzing_text(frag)
                        f.write(f"<div class=\"note-entry\">{html.escape(display_frag)}")
                        for entry in frag_map.get(idx,[]):
                            render_shot_block(entry,base,dns,f)
                        f.write("</div>")
                elif note_text:
                    cleaned=sanitize_fuzzing_text(note_text)
                    f.write(f"<div class=\"note-entry\">{html.escape(cleaned)}</div>")
                if extras:
                    f.write("<div class=\"note-entry\">")
                    for entry in extras:
                        render_shot_block(entry,base,dns,f)
                    f.write("</div>")
                f.write("</td>")
            f.write("</tr>\n")
        f.write("</tbody>\n</table>\n</body>\n</html>\n")
    print(f"[+] Wrote HTML: {path}")

def main():
    p=argparse.ArgumentParser(description="Generate EyeWitness HTML report from new-recon CSV data.")
    p.add_argument("input_csv",help="CSV from new-recon (after ai-notes).")
    p.add_argument("-o","--output-csv",help="Optional CSV to write enriched data (default: skip CSV).")
    p.add_argument("--output-html",help="HTML report path (default: <input>_screenshots.html).")
    p.add_argument("--max-hosts-per-row",type=int,default=25,help="Limit number of hostnames parsed per row.")
    p.add_argument("--include-boring",action="store_true",help="Include rows without interesting Notes/Nuclei.")
    p.add_argument("--targets-file",help="Where to write EyeWitness targets list (default: <screenshot-dir>/targets.txt).")
    p.add_argument("--screenshot-dir",default="eyewitness-output",help="EyeWitness output directory.")
    p.add_argument("--eyewitness-root",default="~/EyeWitness",help="Path to EyeWitness project root (default: ~/EyeWitness).")
    p.add_argument("--eyewitness-python",help="Path to EyeWitness python interpreter (default: auto-detect, try eyewitness-venv/bin/python).")
    p.add_argument("--eyewitness-script",help="Path to EyeWitness.py (default: ./Python/EyeWitness.py).")
    p.add_argument("--eyewitness-timeout",type=int,default=25,help="EyeWitness timeout seconds per target.")
    p.add_argument("--eyewitness-extra",nargs=argparse.REMAINDER,help="Additional arguments to pass to EyeWitness (appended at end).")
    args=p.parse_args()

    with open(args.input_csv,encoding="utf-8-sig",newline="") as f:
        reader=csv.DictReader(f)
        fieldnames=normalize_fieldnames(reader.fieldnames)
        reader.fieldnames=fieldnames
        ensure_required_fields(fieldnames)
        rows=list(reader)

    per_row_targets,all_targets=build_targets(rows,args.max_hosts_per_row,not args.include_boring)
    total=len(all_targets)
    default_html=args.output_html or f"{os.path.splitext(args.input_csv)[0]}_screenshots.html"
    chrome_bin=shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    custom_dir=os.path.abspath(os.path.join(args.screenshot_dir,"custom-shots"))
    if not total:
        print("[i] No matching HTTP targets found; nothing to do.")
        updated=update_rows(rows,per_row_targets,{},[],{},custom_dir,chrome_bin)
        write_html_output(updated,default_html)
        if args.output_csv:
            write_csv_output(updated,args.output_csv)
        return

    screenshot_dir=os.path.abspath(args.screenshot_dir)
    custom_dir=os.path.join(screenshot_dir,"custom-shots")
    targets_file=os.path.abspath(args.targets_file or os.path.join(screenshot_dir,"targets.txt"))
    write_targets_file(all_targets,targets_file)
    print(f"[i] Wrote {total} targets -> {targets_file}")

    python_bin=resolve_eyewitness_python(args.eyewitness_python,args.eyewitness_root)
    script_path=resolve_eyewitness_script(args.eyewitness_script,args.eyewitness_root)
    eyewitness_root=None
    if script_path:
        eyewitness_root=os.path.dirname(os.path.dirname(script_path)) if script_path.endswith("EyeWitness.py") else os.path.dirname(script_path)
    out_dir=os.path.abspath(screenshot_dir)
    exec_targets=targets_file
    cleanup_target=None
    if eyewitness_root:
        exec_targets=os.path.join(eyewitness_root,"targets_autogen.txt")
        shutil.copyfile(targets_file,exec_targets)
        cleanup_target=exec_targets
    shots=[]
    thumbs={}
    mapping={}
    try:
        if not python_bin or not script_path:
            print("[!] EyeWitness python or script not found; screenshots will be marked pending.")
            shots=[]
        else:
            ensure_dir(out_dir)
            extra=build_default_extra(args.eyewitness_extra)
            ok=run_eyewitness(python_bin,script_path,exec_targets,out_dir,extra,args.eyewitness_timeout,eyewitness_root)
            if ok:
                print(f"[i] EyeWitness finished, collecting screenshots from {out_dir}")
                mapping=load_eyewitness_mapping(out_dir)
                shots=build_screenshot_index(out_dir)
                thumbs=generate_thumbnails(shots,out_dir)
            else:
                print("[!] EyeWitness run failed; screenshots will be marked pending.")
                shots=[]
                thumbs={}
    finally:
        if cleanup_target and os.path.exists(cleanup_target):
            try:
                os.remove(cleanup_target)
            except OSError:
                pass

    updated_rows=update_rows(rows,per_row_targets,mapping,shots,thumbs,custom_dir,chrome_bin)
    write_html_output(updated_rows,default_html)
    if args.output_csv:
        write_csv_output(updated_rows,args.output_csv)
    win_path=to_windows_path(default_html)
    if win_path:
        print(f"[i] Windows path: {win_path}")

if __name__=="__main__":
    main()
