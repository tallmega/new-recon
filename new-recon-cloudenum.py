#!/usr/bin/env python3
"""Utility helpers for summarizing new-recon output CSVs and cloud hunting."""
import argparse
import csv
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
from threading import Lock
try:
    from alive_progress import alive_bar
    HAS_ALIVE=True
except Exception:
    HAS_ALIVE=False
# above import replaced

COMMON_TLDS={"com","net","org","ca","co","io","gov","edu","mil","int","biz","info"}
GENERIC_SUFFIXES=[
    "companies","company","corp","corporation","group","services","service","solutions","solution",
    "systems","system","support","apps","app","cloud","online","portal","prod","production",
    "dev","development","stage","staging","test","testing","internal","intranet","net","web"
]
GENERIC_PREFIXES={"the","my","app","portal","service"}
MUTATIONS_FILE="/usr/lib/cloud-enum/enum_tools/fuzz.txt"
BASE_LIMIT=3
ROOT_LIMIT=2
CATEGORY_LABELS={
    "gcp-bucket-enum":"Google Cloud Storage",
    "aws-s3-bucket-enum":"AWS S3 Bucket",
    "azure-blob-container-enum":"Azure Blob Storage",
    "azure-blob-enum":"Azure Blob Storage",
    "oracle-bucket-enum":"Oracle Object Storage",
    "ibm-cloud-bucket-enum":"IBM Cloud Object Storage",
    "wasabi-bucket-enum":"Wasabi Bucket",
    "digitalocean-space-enum":"DigitalOcean Space",
    "cloudfront-cdn-enum":"CloudFront CDN",
    "akamai-edge-enum":"Akamai Edge",
    "fastly-cdn-enum":"Fastly CDN",
    "keycdn-enum":"KeyCDN",
    "stackpath-cdn-enum":"StackPath CDN",
    "vercel-bucket-enum":"Vercel Bucket",
    "netlify-bucket-enum":"Netlify Bucket",
    "backblaze-b2-bucket-enum":"Backblaze B2",
}


def extract_labels(dns_cell):
    if not dns_cell:
        return [],[]
    hosts=[h.strip() for h in re.split(r"[\s,]+",dns_cell) if h.strip()]
    slabs=[]
    base_tokens=[]
    for host in hosts:
        parts=[lbl for lbl in host.split('.') if lbl]
        if len(parts)>=2:
            tld=parts[-1].lower()
            if tld in COMMON_TLDS and len(parts)>=2:
                sld=parts[-2].lower()
            else:
                sld=parts[-1].lower()
            slabs.append(sld)
            root=extract_root_token(sld)
            if root:
                base_tokens.append(root)
    return slabs, base_tokens


def extract_root_token(label:str) -> str:
    label=label.lower()
    for prefix in GENERIC_PREFIXES:
        if label.startswith(prefix) and len(label)>len(prefix)+2:
            label=label[len(prefix):]
    changed=True
    while changed:
        changed=False
        for suffix in sorted(GENERIC_SUFFIXES,key=len,reverse=True):
            if label.endswith(suffix) and len(label)>len(suffix)+1:
                label=label[:-len(suffix)]
                changed=True
    label=re.sub(r"[\d_-]+$","",label)
    return label


def clean_text(text):
    return re.sub(r"[^a-z0-9.-]","",text.lower())


def append_name(name,collector):
    if name and len(name)<=63 and name not in collector:
        collector.append(name)


def build_names(base_list,mutations):
    results=[]
    for base in base_list:
        base=clean_text(base)
        append_name(base,results)
        for mutation in mutations:
            mutation=clean_text(mutation)
            append_name(f"{base}{mutation}",results)
            append_name(f"{base}.{mutation}",results)
            append_name(f"{base}-{mutation}",results)
            append_name(f"{mutation}{base}",results)
            append_name(f"{mutation}.{base}",results)
            append_name(f"{mutation}-{base}",results)
    print(f"[i] Mutated candidates: {len(results)}")
    return results


def pick_keywords(base_counter,root_counter,base_limit=BASE_LIMIT,root_limit=ROOT_LIMIT):
    keywords=[]
    for label,_ in base_counter.most_common(base_limit):
        if label not in keywords:
            keywords.append(label)
    for label,_ in root_counter.most_common(root_limit):
        if label and label not in keywords:
            keywords.append(label)
    return keywords


def run_cloud_enum(entries, workers=5, delay=0.1, debug=False):
    if not entries:
        print("[!] No cloud enum entries available")
        return defaultdict(set)
    total=len(entries)
    print(f"[i] nuclei cloud enum with {total} entries (workers={workers}, delay={delay}s)")

    lock=Lock()
    findings=defaultdict(set)

    template_error=[False]
    template_updated=[False]
    retry_queue=[]

    def _update_templates():
        cmd=["nuclei","-update-templates"]
        try:
            subprocess.run(cmd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        except FileNotFoundError:
            raise RuntimeError("nuclei binary not found; unable to update templates")
        except subprocess.CalledProcessError as exc:
            msg="\n".join(filter(None,[exc.stdout,exc.stderr])).strip()
            raise RuntimeError(f"nuclei template update failed: {msg or exc}")

    def _run(word,retry=False):
        cmd=[
            "nuclei",
            "-silent",
            "-nc",
            "-esc",
            "-t",
            "cloud/enum/",
            "-var",
            f"wordlist={word}",
        ]
        if debug:
            print("[dbg] "+" ".join(cmd))
        try:
            result=subprocess.run(cmd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            output=(result.stdout or "").strip()
            if output:
                for line in output.splitlines():
                    line=line.strip()
                    if not line:
                        continue
                    match=re.match(r"\[[^\]]+:([^\]]+)\]\s+\[[^\]]+\]\s+\[[^\]]+\]\s+(\S+)",line)
                    if match:
                        name=match.group(1).strip()
                        url=match.group(2).strip()
                        category=CATEGORY_LABELS.get(name,name)
                        with lock:
                            findings[category].add(url)
                    if debug:
                        print(line)
            elif debug:
                err=(result.stderr or "").strip()
                if err:
                    print(err)
        except FileNotFoundError:
            raise RuntimeError("nuclei binary not found; aborting cloud enumeration")
        except subprocess.CalledProcessError as exc:
            msg="\n".join(filter(None,[exc.stdout,exc.stderr])).strip()
            msg_lower=msg.lower()
            if any(token in msg_lower for token in ["no templates provided","could not run nuclei","no valid templates"]):
                if not template_updated[0]:
                    template_updated[0]=True
                    print("[i] Updating nuclei templates (auto-detected missing cloud/enum templates)...")
                    _update_templates()
                    retry_queue.append(word)
                    return
                elif not retry:
                    retry_queue.append(word)
                    return
            truncated=msg.splitlines()[0] if msg else ""
            print(f"[!] nuclei cloud scan for '{word}' exited with {exc.returncode}: {truncated}")
        finally:
            if delay>0:
                time.sleep(delay)

    def _execute(wordlist,retry=False):
        with ThreadPoolExecutor(max_workers=max(1,workers)) as executor:
            future_map={executor.submit(_run,word,retry):word for word in wordlist}
            iterator=as_completed(future_map)
            if HAS_ALIVE:
                with alive_bar(len(wordlist),title="cloud enum",enrich_print=False) as bar:
                    for fut in iterator:
                        fut.result()
                        bar()
            else:
                for idx,fut in enumerate(iterator,1):
                    fut.result()
                    if idx % 200==0 or idx==len(wordlist):
                        print(f"    processed {idx}/{len(wordlist)}")

    try:
        _execute(entries, retry=False)
        if retry_queue:
            retry_words=list(dict.fromkeys(retry_queue))
            print(f"[i] Retrying {len(retry_words)} entries after template update...")
            retry_queue.clear()
            _execute(retry_words, retry=True)
    except RuntimeError as exc:
        print(f"[!] {exc}")
    return findings


def main():
    parser=argparse.ArgumentParser(description="new-recon stats helper")
    parser.add_argument("csv",help="Path to new-recon-*_output_ffuf.csv")
    parser.add_argument("--top",type=int,default=10,help="How many results to display (default 10)")
    parser.add_argument("--cloud-workers",type=int,default=5,help="Parallel nuclei workers for cloud enum (default 5)")
    parser.add_argument("--cloud-delay",type=float,default=0.0,help="Delay in seconds between nuclei runs to avoid throttling (default 0.0)")
    parser.add_argument("--cloud-debug",action="store_true",help="Print nuclei commands and output for debugging")
    args=parser.parse_args()

    base_counter=Counter()
    root_counter=Counter()
    with open(args.csv,encoding="utf-8-sig") as f:
        reader=csv.DictReader(f)
        for row in reader:
            bases,roots=extract_labels(row.get("DNS",""))
            base_counter.update(bases)
            root_counter.update(roots)

    if not base_counter:
        print("[!] No DNS data found.")
        return

    print(f"[i] Top {args.top} base domains (SLDs) in {os.path.basename(args.csv)}")
    for label,count in base_counter.most_common(args.top):
        print(f"{label}\t{count}")
    if root_counter:
        print(f"\n[i] Candidate company keywords")
        for label,count in root_counter.most_common(args.top):
            print(f"{label}\t{count}")

    keywords=pick_keywords(base_counter,root_counter)
    print(f"\n[i] Cloud hunt keywords (top {BASE_LIMIT} bases + {ROOT_LIMIT} roots): {', '.join(keywords)}")
    try:
        with open(MUTATIONS_FILE,encoding="utf-8",errors="ignore") as infile:
            mutations=[line.strip() for line in infile if line.strip()]
    except FileNotFoundError:
        print(f"[!] Mutations file not found: {MUTATIONS_FILE}")
        mutations=[]
    print(f"[i] Mutations loaded: {len(mutations)}")
    word_entries=build_names(keywords,mutations)
    findings=run_cloud_enum(word_entries,workers=args.cloud_workers,delay=args.cloud_delay,debug=args.cloud_debug)
    if findings and any(findings.values()):
        print("\n[i] Potential Cloud Assets Discovered:")
        for category in sorted(findings.keys()):
            print(f"{category}:")
            for url in sorted(findings[category]):
                print(f"- {url}")
            print()
    else:
        print("\n[i] No cloud assets discovered.")


if __name__=="__main__":
    main()
