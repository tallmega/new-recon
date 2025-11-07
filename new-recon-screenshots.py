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
from typing import Dict, List, Optional, Sequence, Tuple

_HAS_ALIVE=False
try:
    from alive_progress import alive_it
    _HAS_ALIVE=True
except Exception:
    _HAS_ALIVE=False

HTTP_PORTS={80,81,3000,5000,7001,7080,7081,7443,8000,8008,8080,8081,8088,
            8181,8443,8448,8880,8888,9000,9080,9090,9200,9443,10000,10443,
            11080,12000,12345,16080,18080,443,4443,4444,451,591,593,8320}

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

def build_targets(rows:List[Dict[str,str]],max_hosts:int,only_interesting:bool) -> Tuple[List[List[Target]],Dict[Target,Target]]:
    per_row=[]
    unique={}
    for row in rows:
        hosts=split_hosts(row.get("DNS",""),max_hosts)
        if not hosts:
            ip=extract_ip(row.get("IP / Hosting Provider",""))
            if ip:
                hosts=[ip]
        ports=parse_ports_cell(row.get("Ports",""))
        http_ports=select_http_ports(ports)
        if not hosts or not http_ports:
            per_row.append([])
            continue
        if only_interesting and not is_interesting_row(row.get("Nuclei",""),row.get(NOTES_COL,"")):
            per_row.append([])
            continue
        row_targets=[]
        for host in hosts:
            for port in http_ports:
                tgt=Target(host=host,port=port,scheme=port_scheme(port))
                row_targets.append(tgt)
                unique.setdefault(tgt,tgt)
        per_row.append(row_targets)
    return per_row,unique

def ensure_dir(path:str) -> None:
    os.makedirs(path,exist_ok=True)

def write_targets_file(targets:Dict[Target,Target],path:str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path,"w",encoding="utf-8") as f:
        for tgt in sorted(targets.values(),key=lambda t:(t.host,t.port)):
            url=f"{tgt.scheme}://{tgt.host}:{tgt.port}"
            f.write(url+"\n")

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

def load_eyewitness_mapping(base_dir:str) -> Dict[Tuple[str,int],str]:
    mapping={}
    report=os.path.join(base_dir,"report.json")
    candidates=[]
    if os.path.isfile(report):
        candidates.append(report)
    legacy=os.path.join(base_dir,"results.json")
    if os.path.isfile(legacy):
        candidates.append(legacy)
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
                url=entry.get("url") or entry.get("final_url") or entry.get("input_url")
                screenshot=(entry.get("screenshot") or entry.get("screenshot_path") or entry.get("image"))
                if not url or not screenshot:
                    continue
                try:
                    parsed=urlparse(url)
                    host=canonical_host(parsed.hostname or "")
                    port=parsed.port or (443 if parsed.scheme=="https" else 80)
                except Exception:
                    continue
                shot_path=os.path.join(base_dir,screenshot) if not os.path.isabs(screenshot) else screenshot
                mapping[(host,port)]=shot_path
        except Exception:
            continue
    # Fallback to urls.csv if mapping still empty
    if not mapping:
        csv_path=os.path.join(base_dir,"urls.csv")
        if os.path.isfile(csv_path):
            try:
                with open(csv_path,newline="",encoding="utf-8") as f:
                    reader=csv.DictReader(f)
                    for row in reader:
                        url=row.get("URL") or row.get("Url") or row.get("url")
                        screenshot=row.get("Screenshot Path") or row.get("Screenshot") or row.get("screenshot")
                        if not url or not screenshot:
                            continue
                        try:
                            parsed=urlparse(url)
                            host=canonical_host(parsed.hostname or "")
                            port=parsed.port or (443 if parsed.scheme=="https" else 80)
                        except Exception:
                            continue
                        shot_path=os.path.join(base_dir,screenshot) if not os.path.isabs(screenshot) else screenshot
                        mapping.setdefault((host,port),shot_path)
            except Exception:
                pass
    return mapping

def sanitize(s:str) -> str:
    return re.sub(r"[^0-9A-Za-z]+","_",s)

def locate_screenshot(target:Target,mapping:Dict[Tuple[str,int],str],shots:List[str]) -> str:
    key=(canonical_host(target.host),target.port)
    if key in mapping and os.path.isfile(mapping[key]):
        return mapping[key]
    # Attempt alternate keys (common 80/443 mapping when scheme forced)
    alt_key=(key[0],80 if target.scheme=="http" else 443)
    if alt_key in mapping and os.path.isfile(mapping[alt_key]):
        return mapping[alt_key]
    # Fallback to fuzzy match
    host_key=canonical_host(target.host)
    port_str=str(target.port)
    for path in shots:
        name=os.path.basename(path).lower()
        if host_key in name and port_str in name:
            return path
    for path in shots:
        name=os.path.basename(path).lower()
        if host_key in name:
            return path
    return ""

def to_windows_path(path:str) -> Optional[str]:
    distro=os.environ.get("WSL_DISTRO_NAME")
    if not distro:
        return None
    rel=os.path.relpath(os.path.abspath(path),"/")
    return f"\\\\wsl$\\{distro}\\{rel.replace('/', '\\')}"


def update_rows(rows:List[Dict[str,str]],per_row_targets:List[List[Target]],mapping:Dict[Tuple[str,int],str],shots:List[str],thumbs:Dict[str,str]) -> List[Dict[str,str]]:
    updated=[]
    for row,row_targets in zip(rows,per_row_targets):
        new_row={
            "DNS":row.get("DNS",""),
            "IP / Hosting Provider":row.get("IP / Hosting Provider",""),
            "Ports":row.get("Ports",""),
            "notes_text":row.get("Notes","") or ""
        }
        fragments=[]
        target_entries=[]
        shot_groups={}
        pending_labels=[]
        for tgt in row_targets:
            shot=locate_screenshot(tgt,mapping,shots)
            label=f"{tgt.host}:{tgt.port}"
            if shot:
                shot_groups.setdefault(shot,[]).append(label)
            else:
                pending_labels.append(label)
        unique_shots=list(shot_groups.items())
        if unique_shots:
            single=len(unique_shots)==1
            for shot,labels_list in unique_shots:
                display_label="" if single else ", ".join(labels_list)
                if display_label:
                    fragments.append(f"{display_label} -> {shot}")
                else:
                    fragments.append(shot)
                target_entries.append({
                    "label":display_label,
                    "path":shot,
                    "thumb":thumbs.get(shot,shot),
                    "pending":False
                })
        for label in pending_labels:
            fragments.append(f"{label} -> (pending)")
            target_entries.append({"label":label,"path":"","thumb":"","pending":True})
        new_row["Screenshot"]=" ; ".join(fragments)
        new_row["_targets"]=target_entries
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

def write_html_output(rows:List[Dict[str,str]],path:str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    base=os.path.dirname(os.path.abspath(path)) or "."
    with open(path,"w",encoding="utf-8") as f:
        f.write("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
        f.write(
            "<style>"
            "body{font-family:Arial,Helvetica,sans-serif;margin:20px;}"
            "table{border-collapse:collapse;width:100%;border:1px solid #000;background:#fff;}"
            "th,td{border:1px solid #000;padding:8px 10px;vertical-align:top;font-size:9pt;}"
            "th{background:#000;color:#ffd400;font-weight:bold;}"
            "tbody tr:nth-child(odd) td{background:#f7f7f7;}"
            "tbody tr:nth-child(even) td{background:#ededed;}"
            "td img{max-width:20%;height:auto;border:1px solid #888;margin:6px auto;display:block;}"
            ".shot-block{margin:0 auto 10px auto;text-align:center;}"
            ".shot-pending{font-style:italic;color:#666;}"
            ".col-ip{width:20%;}"
            ".col-port{width:10%;}"
            ".note-text{margin-bottom:10px;font-style:italic;text-align:left;}"
            "</style>\n"
        )
        f.write("</head>\n<body>\n")
        f.write("<table>\n<thead><tr><th>FQDN</th><th class=\"col-ip\">First Resolved IP</th><th class=\"col-port\">Ports</th><th>Notes and Screenshots</th></tr></thead>\n<tbody>\n")
        for row in rows:
            dns=html.escape(row.get("DNS",""))
            resolved_ip=extract_ip(row.get("IP / Hosting Provider","")) or row.get("IP / Hosting Provider","")
            ip=html.escape(resolved_ip)
            ports=html.escape(row.get("Ports",""))
            note_text=html.escape(row.get("notes_text","").strip())
            f.write("<tr>")
            f.write(f"<td>{dns}</td><td class=\"col-ip\">{ip}</td><td class=\"col-port\">{ports}</td>")
            shots=row.get("_targets") or []
            if not shots:
                if note_text:
                    f.write(f"<td><div class=\"note-text\">{note_text}</div></td>")
                else:
                    f.write("<td></td>")
            else:
                f.write("<td>")
                if note_text:
                    f.write(f"<div class=\"note-text\">{note_text}</div>")
                for entry in shots:
                    if entry.get("pending"):
                        f.write("<div class=\"shot-block\"></div>")
                        continue
                    thumb_path=entry.get("thumb") or entry.get("path")
                    if not thumb_path:
                        continue
                    rel=os.path.relpath(thumb_path,base)
                    rel_html=html.escape(rel)
                    f.write("<div class=\"shot-block\">")
                    f.write(f"<img src=\"{rel_html}\" alt=\"{dns}\">")
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

    per_row_targets,unique_targets=build_targets(rows,args.max_hosts_per_row,not args.include_boring)
    total=len(unique_targets)
    default_html=args.output_html or f"{os.path.splitext(args.input_csv)[0]}_screenshots.html"
    if not total:
        print("[i] No matching HTTP targets found; nothing to do.")
        updated=update_rows(rows,per_row_targets,{},[],{})
        write_html_output(updated,default_html)
        if args.output_csv:
            write_csv_output(updated,args.output_csv)
        return

    screenshot_dir=os.path.abspath(args.screenshot_dir)
    targets_file=os.path.abspath(args.targets_file or os.path.join(screenshot_dir,"targets.txt"))
    write_targets_file(unique_targets,targets_file)
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

    updated_rows=update_rows(rows,per_row_targets,mapping,shots,thumbs)
    write_html_output(updated_rows,default_html)
    if args.output_csv:
        write_csv_output(updated_rows,args.output_csv)
    win_path=to_windows_path(default_html)
    if win_path:
        print(f"[i] Windows path: {win_path}")

if __name__=="__main__":
    main()
