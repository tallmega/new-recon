#!/usr/bin/env python3
import argparse, csv, ipaddress, os, re, socket, subprocess, sys, time, uuid
from collections import defaultdict
from functools import lru_cache
from threading import Thread
import dns.resolver

DEFAULT_DNS_RESOLVERS=["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4"]
def _default_dns_wordlist():
    env=os.environ.get("DNS_WORDLIST")
    if env:
        return env
    pwd=os.getcwd()
    candidates=[
        os.path.join(pwd,"SecLists","Discovery","DNS","subdomains-top1million-5000.txt"),
        os.path.join(pwd,"SecLists","Discovery","DNS","dns-Jhaddix.txt"),
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None
DEFAULT_DNS_WORDLIST=_default_dns_wordlist()

_HAS_ALIVE=False
try:
    from alive_progress import alive_bar
    _HAS_ALIVE=True
except Exception:
    _HAS_ALIVE=False

def run_with_spinner(label, fn):
    if not _HAS_ALIVE:
        return fn()
    result={'value':None}
    error={}
    def _runner():
        try:
            result['value']=fn()
        except Exception as exc:
            error['exc']=exc
    t=Thread(target=_runner,daemon=True)
    t.start()
    with alive_bar(total=None,title=label,bar='classic',spinner='dots_waves2') as bar:
        while t.is_alive():
            time.sleep(0.1)
            bar()
    t.join()
    if error:
        raise error['exc']
    return result['value']

# ---------- helpers ----------
def expand_cidr(cidr):
    try: return [str(ip) for ip in ipaddress.ip_network(cidr, strict=False)]
    except Exception: return []

def process_input_file(path):
    s=set()
    with open(path) as f:
        for l in f:
            l=l.strip()
            if not l: continue
            s.update(expand_cidr(l) if '/' in l else [l])
    return s

def is_ip(v):
    try: ipaddress.ip_address(v); return True
    except: return False

def ip_sort_key(v):
    try:
        ip=ipaddress.ip_address(v)
        return (0 if ip.version==4 else 1,int(ip))
    except: return (2,v)

def proto_port_sort_key(p):
    try:
        proto,port=p.split('/')
        return (int(port),proto)
    except: return (99999,p)

def configure_dns_resolver(nameservers,timeout=2.0,lifetime=4.0):
    if not nameservers: return
    resolver=dns.resolver.Resolver(configure=False)
    resolver.nameservers=list(dict.fromkeys(nameservers))
    resolver.timeout=timeout
    resolver.lifetime=lifetime
    dns.resolver.default_resolver=resolver

# ---------- dns ----------
@lru_cache(maxsize=10000)
def resolve_cname_chain(t):
    cur=t.rstrip('.'); seen=set()
    while True:
        if cur in seen: break
        seen.add(cur)
        try:
            ans=dns.resolver.resolve(cur,'CNAME')
            if ans: cur=str(ans[0].target).rstrip('.'); continue
        except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,
                dns.resolver.Timeout,dns.resolver.NoNameservers):
            pass
        break
    return cur

@lru_cache(maxsize=10000)
def resolve_a_aaaa(t):
    a,aaaa=[],[]
    t=t.rstrip('.')
    try: a=[str(r) for r in dns.resolver.resolve(t,'A')]
    except: pass
    try: aaaa=[str(r) for r in dns.resolver.resolve(t,'AAAA')]
    except: pass
    return a,aaaa

def choose_ips_for_fqdn(fqdn,scan_all=False,input_ips=None,prefer_input_ip=False):
    input_ips=input_ips or set()
    final=resolve_cname_chain(fqdn)
    a,aaaa=resolve_a_aaaa(final)
    all_ips=a+aaaa
    if not all_ips:
        try: all_ips=socket.gethostbyname_ex(fqdn)[2]
        except: return []
    if prefer_input_ip:
        for ip in sorted(all_ips,key=ip_sort_key):
            if ip in input_ips:
                return [ip] if not scan_all else sorted(all_ips,key=ip_sort_key)
    if scan_all: return sorted(all_ips,key=ip_sort_key)
    v4=[i for i in all_ips if ipaddress.ip_address(i).version==4]
    v6=[i for i in all_ips if ipaddress.ip_address(i).version==6]
    if v4: return [sorted(v4,key=ip_sort_key)[0]]
    if v6: return [sorted(v6,key=ip_sort_key)[0]]
    return [sorted(all_ips,key=ip_sort_key)[0]]

def resolve_ips(fqdn):
    a,aaaa=resolve_a_aaaa(fqdn)
    return set(a)|set(aaaa)

def detect_dns_wildcard(domain,attempts=3):
    wildcard_sets=[]
    for _ in range(attempts):
        label=uuid.uuid4().hex[:16]
        test=f"{label}.{domain.lstrip('.')}"
        ips=resolve_ips(test)
        if ips: wildcard_sets.append(ips)
    if len(wildcard_sets)<2: return set()
    first=wildcard_sets[0]
    if all(s==first for s in wildcard_sets[1:]):
        return first
    return set()

def filter_wildcard_hosts(hosts,wildcard_ips):
    if not wildcard_ips: return set(hosts),set()
    clean=set(); removed=set()
    for h in hosts:
        ips=resolve_ips(h)
        if ips and ips.issubset(wildcard_ips):
            removed.add(h)
        else:
            clean.add(h)
    return clean,removed

# ---------- scanning ----------
def scan_ports(ip,skip=False,nmap_top_ports=5000,nmap_timeout="90s"):
    if skip: return 'N/A'
    ip_str=str(ip)
    try: is6=ipaddress.ip_address(ip_str).version==6
    except: return 'N/A'
    cmd=['nmap','-Pn','--top-ports',str(nmap_top_ports),
         '--host-timeout',str(nmap_timeout),ip_str]
    if is6: cmd.insert(1,'-6')
    print(f"[i] Scanning {ip_str} (top {nmap_top_ports})")
    ports=set()
    try:
        out=subprocess.run(cmd,stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,
                           encoding='utf-8').stdout
        for line in out.splitlines():
            m=re.match(r"^(\d+)\/([a-zA-Z]+)\s+open",line)
            if m: ports.add(f"{m.group(2).lower()}/{m.group(1)}")
    except FileNotFoundError:
        print("[!] nmap not found"); return 'N/A'
    return ports

def format_target(h,p):
    try:
        if ipaddress.ip_address(h).version==6:
            return f"[{h}]:{p}"
    except: pass
    return f"{h}:{p}"

def run_nuclei(host,port):
    target=format_target(host,port)
    try:
        proc=subprocess.Popen(
            ["nuclei","-silent","-nc","-t","exposed-panels/","-t","technologies/","-u",target],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except FileNotFoundError: return ''
    out,_=proc.communicate()
    txt=out.decode(errors='ignore').strip()
    if not txt: return ''
    # Filter nuclei output for meaningful tags
    tags=set()
    for line in txt.splitlines():
        for t in re.findall(r'\[([^\]]+)\]',line):
            tl=t.lower()
            if any(x in tl for x in ['http','info','ssl','tcp','udp']): continue
            parts=tl.split(':')
            tags.add(parts[-1])
    return ', '.join(sorted(tags))

# ---------- csv ----------
def write_csv(outfile,data):
    with open(outfile,'w',newline='\n') as f:
        fn=['DNS','IP / Hosting Provider','Ports','Nuclei','Notes']
        w=csv.DictWriter(f,fieldnames=fn); w.writeheader()
        for ip,recs in sorted(data.items(),key=lambda x:ip_sort_key(x[0])):
            dns=', '.join(sorted(set(r['dns'] for r in recs if r['dns'])))
            ports=set(); nuc=set(); all_na=True
            for r in recs:
                op=r['ports']
                if isinstance(op,str) and op=='N/A': continue
                all_na=False
                if isinstance(op,set): ports|=op
                if r['nuclei']: nuc|={r['nuclei']}
            ports_str='N/A' if all_na else ('None' if not ports else ', '.join(sorted(ports,key=proto_port_sort_key)))
            nuc_str=', '.join(sorted(x for x in nuc if x))
            w.writerow({'DNS':dns,'IP / Hosting Provider':ip,'Ports':ports_str,'Nuclei':nuc_str,'Notes':''})
    print(f"[i] CSV written: {outfile}")

# ---------- enumeration helpers ----------
def run_subfinder(domain,resolvers=None):
    cmd=["subfinder","-d",domain,"-silent","-all"]
    if resolvers:
        cmd+=["-r",",".join(resolvers)]
    hosts=set()
    try:
        out=run_with_spinner(f"subfinder on {domain}",
                             lambda: subprocess.check_output(cmd,encoding='utf-8',stderr=subprocess.PIPE))
        hosts|={line.strip() for line in out.splitlines() if line.strip()}
    except FileNotFoundError:
        print("[!] subfinder not found; skipping")
    except subprocess.CalledProcessError as exc:
        stderr=(exc.stderr or "").strip()
        if stderr:
            print(f"[!] subfinder error ({domain}): {stderr}")
        else:
            print(f"[!] subfinder error ({domain}): returned exit code {exc.returncode}")
    return hosts

def run_gobuster(domain,wordlist,resolvers=None,threads=50,force_wildcard=True):
    if not wordlist:
        return set()
    if not os.path.isfile(wordlist):
        print(f"[!] gobuster wordlist not found: {wordlist}")
        return set()
    cmd=["gobuster","dns","-d",domain,"-q","-w",wordlist,"--show-ips"]
    if threads:
        cmd+=["-t",str(threads)]
    if force_wildcard:
        cmd.append("--wildcard")
    if resolvers:
        for r in resolvers:
            cmd+=["-r",r]
    hosts=set()
    try:
        proc=run_with_spinner(f"gobuster on {domain}",
                              lambda: subprocess.run(cmd,stdout=subprocess.PIPE,
                                                     stderr=subprocess.PIPE,encoding='utf-8',check=False))
    except FileNotFoundError:
        print("[!] gobuster not found; skipping")
        return set()
    stderr_lines=[l.strip() for l in proc.stderr.splitlines() if l.strip()]
    for line in stderr_lines:
        print(f"[gobuster] {line}")
    for line in proc.stdout.splitlines():
        m=re.match(r"Found:\s+([^ \[\t]+)",line)
        if not m: continue
        host=m.group(1).rstrip('.')
        if host: hosts.add(host)
    return hosts

# ---------- domain scan ----------
def scan_domain(domain,input_ips,skip=False,scan_all=False,prefer_input_ip=False,
                nmap_top_ports=500,nmap_timeout="90s",nuclei_single_web_port=True,
                resolvers=None,apply_wildcard_filter=True,gobuster_wordlist=None,
                gobuster_threads=50,use_gobuster=True):
    print(f"[i] Enumerating {domain}")
    wildcard_ips=set()
    wildcard_hits=set()
    if apply_wildcard_filter:
        wildcard_ips=detect_dns_wildcard(domain)
        if wildcard_ips:
            print(f"[i] Wildcard detected for {domain}: {', '.join(sorted(wildcard_ips,key=ip_sort_key))}")
    subs=set()
    if wildcard_ips:
        print("[i] Skipping subfinder because wildcard DNS is present")
    else:
        subs=run_subfinder(domain,resolvers)
        if subs:
            print(f"[i] subfinder discovered {len(subs)} names for {domain}")
            subs,removed=filter_wildcard_hosts(subs,wildcard_ips)
            wildcard_hits|=removed
    if use_gobuster:
        if not gobuster_wordlist:
            print("[i] Skipping gobuster (no wordlist provided)")
        else:
            print(f"[i] Starting gobuster dns on {domain} with {gobuster_threads} threads (wordlist: {gobuster_wordlist})")
            gobuster_hosts=run_gobuster(domain,gobuster_wordlist,resolvers,
                                        threads=gobuster_threads,force_wildcard=True)
            if gobuster_hosts:
                print(f"[i] gobuster discovered {len(gobuster_hosts)} names for {domain}")
                filtered,removed=filter_wildcard_hosts(gobuster_hosts,wildcard_ips)
                wildcard_hits|=removed
                new_hosts=filtered-subs
                if new_hosts:
                    print(f"[i] gobuster added {len(new_hosts)} new hostnames")
                subs|=filtered
    if wildcard_hits:
        print(f"[i] Filtered {len(wildcard_hits)} total wildcard hostnames")

    results=defaultdict(list)
    for s in sorted(subs):
        ips=choose_ips_for_fqdn(s,scan_all,input_ips,prefer_input_ip)
        for ip in ips:
            results[str(ip)].append({'dns':s,'ports':set(),'nuclei':''})
    for i in input_ips:
        if is_ip(i): results.setdefault(i,[])

    # nmap
    scanres={ip:scan_ports(ip,skip,nmap_top_ports,nmap_timeout) for ip in results}
    for ip,recs in results.items():
        for r in recs: r['ports']=scanres[ip]

    if not skip:
        print("[i] Running nuclei (smart single-port mode)" if nuclei_single_web_port else "[i] Running nuclei full mode")
        for ip,recs in results.items():
            op=scanres[ip]
            if not isinstance(op,set) or not op: continue
            chosen=None
            if nuclei_single_web_port:
                for cand in [443,8443,80,8080]:
                    if f"tcp/{cand}" in op: chosen=cand; break
                if not chosen:
                    try:
                        _,chosen=next(iter(sorted(op,key=proto_port_sort_key))).split('/')
                        chosen=int(chosen)
                    except: continue
                op={f"tcp/{chosen}"}
            for pp in sorted(op,key=proto_port_sort_key):
                try:
                    _,portnum=pp.split('/')
                    portnum=int(portnum)
                except: continue
                out=run_nuclei(ip,portnum)
                if out:
                    for r in recs: r['nuclei']=out
    return results

# ---------- main ----------
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("domains",nargs="+")
    p.add_argument("-i","--input")
    p.add_argument("--skip-scans",action="store_true")
    p.add_argument("--scan-all-ips-per-fqdn",action="store_true")
    p.add_argument("--prefer-input-ip",action="store_true")
    p.add_argument("--nmap-top-ports",type=int,default=5000)
    p.add_argument("--nmap-timeout",default="90s")
    p.add_argument("--nuclei-single-web-port",action="store_true",default=True)
    p.add_argument("--dns-resolver",action="append",dest="dns_resolvers",
                   help="Custom DNS resolver IP (can be repeated)")
    p.add_argument("--use-system-resolvers",action="store_true",
                   help="Do not override system resolver configuration")
    p.add_argument("--no-wildcard-filter",action="store_true",
                   help="Keep hostnames that match wildcard DNS responses")
    p.add_argument("--gobuster-wordlist",default=DEFAULT_DNS_WORDLIST,
                   help="Wordlist to supply to gobuster dns mode")
    p.add_argument("--gobuster-threads",type=int,default=50,
                   help="Number of gobuster threads")
    p.add_argument("--skip-gobuster",action="store_true",
                   help="Skip gobuster dns enumeration")
    a=p.parse_args()

    ips=process_input_file(a.input) if a.input else set()
    chosen_resolvers=[]
    if not a.use_system_resolvers:
        if a.dns_resolvers:
            chosen_resolvers=a.dns_resolvers
        else:
            chosen_resolvers=DEFAULT_DNS_RESOLVERS
    configure_dns_resolver(chosen_resolvers)

    allres=defaultdict(list)
    for d in a.domains:
        r=scan_domain(d,ips,skip=a.skip_scans,
                      scan_all=a.scan_all_ips_per_fqdn,
                      prefer_input_ip=a.prefer_input_ip,
                      nmap_top_ports=a.nmap_top_ports,
                      nmap_timeout=a.nmap_timeout,
                      nuclei_single_web_port=a.nuclei_single_web_port,
                      resolvers=chosen_resolvers or None,
                      apply_wildcard_filter=not a.no_wildcard_filter,
                      gobuster_wordlist=a.gobuster_wordlist,
                      gobuster_threads=a.gobuster_threads,
                      use_gobuster=not a.skip_gobuster)
        for ip,recs in r.items(): allres[ip].extend(recs)
    outfile=f"{a.domains[0]}_output.csv"
    write_csv(outfile,allres)
