import json
import argparse
import sys
import os
import time
import platform
import subprocess as _subprocess
from datetime import datetime
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
import re
import tldextract

from tools.nmap_tool import NmapTool
from tools.httpx_tool import HttpxTool
from tools.hosting_intel_tool import HostingIntelTool
from tools.safety_validator_tool import SafetyValidatorTool
from tools.ip_rotation_tool import IPRotationTool
from tools.permutation_tool import PermutationTool
from tools.subdomain_enum_tool import SubdomainEnumTool
from tools.vhost_enum_tool import VhostEnumTool
from tools.origin_ip_tool import OriginIpTool
from tools.nuclei_tool import NucleiTool
from tools.spider_tool import SpiderTool
from tools.js_analyzer_tool import JsAnalyzerTool
from tools.content_discovery_tool import ContentDiscoveryTool
from tools.dns_manager_tool import DnsManagerTool

class TeeStream:
    """Duplica la scrittura su uno stream originale e su un file di log."""
    def __init__(self, original_stream, log_file):
        self.original = original_stream
        self.log_file = log_file

    def write(self, data):
        self.original.write(data)
        try:
            self.log_file.write(data)
            self.log_file.flush()
        except Exception:
            pass

    def flush(self):
        self.original.flush()
        try:
            self.log_file.flush()
        except Exception:
            pass

    def fileno(self):
        return self.original.fileno()

    def isatty(self):
        return self.original.isatty()


def setup_scan_directory(start_time: datetime, params: dict, args) -> str:
    """
    Crea la cartella di output per la singola run di scansione.
    Struttura: <output_dir>/scan_<scan_type>_<max_depth>_<timestamp>/
    Restituisce il path assoluto della cartella creata.
    """
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    scan_type = params.get("scan_type", "fast")
    max_depth = params.get("max_depth", 5)
    folder_name = f"scan_{scan_type}_{max_depth}_{timestamp}"

    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_output_dir = args.output_dir if args.output_dir else os.path.join(script_dir, "results")
    scan_dir = os.path.join(base_output_dir, folder_name)

    try:
        os.makedirs(scan_dir, exist_ok=True)
    except Exception as e:
        print(f"  [!] Errore nella creazione della directory {scan_dir}: {e}. Uso /tmp come fallback.", file=sys.stderr)
        scan_dir = os.path.join("/tmp", folder_name)
        os.makedirs(scan_dir, exist_ok=True)

    return scan_dir


def save_debug_info(scan_dir: str, args, params: dict, domains: list, start_time: datetime):
    """Salva un file debug_info.txt con informazioni utili al troubleshooting."""
    filepath = os.path.join(scan_dir, "debug_info.txt")
    try:
        lines = []
        lines.append(f"=== ASM Scan Debug Info ===")
        lines.append(f"Scan Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Hostname:   {platform.node()}")
        lines.append(f"OS:         {platform.platform()}")
        lines.append(f"Python:     {sys.version}")
        lines.append(f"CWD:        {os.getcwd()}")
        lines.append(f"Script:     {os.path.abspath(__file__)}")
        lines.append(f"")
        lines.append(f"--- Arguments (CLI) ---")
        for k, v in vars(args).items():
            lines.append(f"  {k}: {v}")
        lines.append(f"")
        lines.append(f"--- Parameters (merged) ---")
        lines.append(json.dumps(params, indent=2))
        lines.append(f"")
        lines.append(f"--- Targets ({len(domains)}) ---")
        for d in domains:
            lines.append(f"  {d}")
        lines.append(f"")
        lines.append(f"--- External Tool Versions ---")
        for tool_name in ["nmap", "puredns", "httpx", "nuclei", "katana", "ffuf", "alterx", "jsluice"]:
            try:
                result = _subprocess.run([tool_name, "--version"], capture_output=True, text=True, timeout=5)
                version = (result.stdout.strip() or result.stderr.strip()).split('\n')[0]
                lines.append(f"  {tool_name}: {version}")
            except Exception:
                lines.append(f"  {tool_name}: non trovato")
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(lines) + '\n')
    except Exception as e:
        print(f"  [!] Errore salvataggio debug_info: {e}", file=sys.stderr)


def safe_load_json(data_str: str) -> dict:
    """Helper per il parsing sicuro dell'output dei tool in formato JSON."""
    try:
        if not data_str or not data_str.strip():
            return {}
        return json.loads(data_str)
    except Exception as e:
        print(f"ATTENZIONE: JSON parser error ({e}) on tool output. Fallback to {{}}.", file=sys.stderr)
        return {}

# regex basica per ipv4, compilata a livello di modulo per ottimizzazione
IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

def group_domains_by_base(domains: List[str]) -> Dict[str, List[str]]:
    """
    Raggruppa una lista di domini in base alla loro root (dominio base).
    Utilizza la libreria tldextract per supportare nativamente tutti i public suffix (inclusi i double TLD).
    Se il target è un IP (IPv4 o IPv6), lo ignora e usa l'IP stesso come "base_domain".
    """
    groups = {}
    
    for d in domains:
        if IPV4_PATTERN.match(d) or ":" in d:
            base = d
        else:
            extracted = tldextract.extract(d)
            # top_domain_under_public_suffix returns the root domain (e.g. google.co.uk)
            base = extracted.top_domain_under_public_suffix if extracted.top_domain_under_public_suffix else d
            
        if base not in groups:
            groups[base] = []
        groups[base].append(d)
    return groups

def get_hostname_from_url(url: str) -> str:
    """
    Estrae l'hostname da un URL (anche senza schema HTTP/S).
    Esempio: "example.com:8080" -> "example.com"
    """
    if "://" not in url:
        return urlparse("//" + url).hostname
    return urlparse(url).hostname

# ==========================================
# FASI DI SCANSIONE (SCANNING PHASES)
# Ogni fase incapsula logiche e tool specifici.
# ==========================================

def run_subdomain_enumeration_phase(domains: List[str], passive_subdomains: dict, params: dict, args: argparse.Namespace, dns_manager: DnsManagerTool, python_dns_resolvers: list) -> Tuple[List[str], dict]:
    """
    Fase 1: Enumerazione dei Sottodomini.
    Scoperta attiva di nuovi domini associati ai target originali.
    - Usa puredns per bruteforce rapido.
    - Genera permutazioni con alterx.
    - Valida i risultati tramite resolver DNS fidati per evitare sinkholing.
    """
    print("\n--- [Fase 1] Subdomain Enumeration Phase ---", file=sys.stderr)
    
    # 1. Bruteforce Attivo
    all_dns_resolvers = dns_manager.get_resolvers(max_count=0)
    subdomain_tool = SubdomainEnumTool(dns_resolvers=all_dns_resolvers)
    subdomain_tool.run(domains, params)
    subdomain_results = safe_load_json(subdomain_tool.get_results())
    
    # Raccoglie i domini base + quelli appena scoperti
    discovered_domains = set(domains)
    for seed, result in subdomain_results.items():
        if "discovered_subdomains" in result:
            discovered_domains.update(result["discovered_subdomains"])
    
    # 2. Generazione e validazione delle Permutazioni
    perm_params_base = {
        "flags": [],
        "scan_type": params.get("scan_type", "fast"),
        "max_wildcards": params.get("max_wildcards", 5)
    } 
    if params.get("scan_type") == "fast":
        perm_params_base["flags"].extend(["-limit", "5000"]) 
    
    permutation_tool = PermutationTool()
    all_valid_permutations = set()

    for seed, result in subdomain_results.items():
        if "error" in result:
             continue
             
        # Combina seed, risultati del bruteforce e input passivi
        group_domains = [seed]
        if "discovered_subdomains" in result:
            group_domains.extend(result["discovered_subdomains"])
            
        passive_for_seed = passive_subdomains.get(seed, [])
        if passive_for_seed:
            group_domains.extend(passive_for_seed)
            
        group_domains = list(set(group_domains))
        if not group_domains:
            continue
        
        # Esegue AlterX
        permutation_tool.run(group_domains, perm_params_base)
        perm_results = safe_load_json(permutation_tool.get_results())

        # Estrae i candidati da validare
        candidates = set()
        if perm_results:
            for p_seed, p_res in perm_results.items():
                if "permutations" in p_res:
                    candidates.update(p_res["permutations"])
        
        # Esclude i domini che già conosciamo essere validi
        candidates -= set(discovered_domains)
        
        # Valida le restanti permutazioni con PureDNS (Resolve)
        if candidates:
            perm_resolve_tool = SubdomainEnumTool(dns_resolvers=python_dns_resolvers)
            perm_resolve_tool.run(list(candidates), {"method": "resolve"})
            resolve_results = safe_load_json(perm_resolve_tool.get_results())
            
            if "resolved_domains" in resolve_results:
                valid = resolve_results["resolved_domains"]["domains"]
                print(f"  [+] {len(valid)} new valid subdomains for {seed}", file=sys.stderr)
                all_valid_permutations.update(valid)
                
                # Associa le permutazioni trovate al seed originario per il JSON finale
                if "permutations" not in subdomain_results[seed]:
                    subdomain_results[seed]["permutations"] = []
                subdomain_results[seed]["permutations"].extend(valid)
        
    if all_valid_permutations:
        print(f"Permutation Scanning Total: trovati {len(all_valid_permutations)} nuovi sottodomini validi.", file=sys.stderr)
        discovered_domains.update(all_valid_permutations)
    else:
        print("Nessuna nuova permutazione valida trovata.", file=sys.stderr)

    expanded_domains = list(discovered_domains)
    print(f"Subdomain enumeration completata. Target parzialmente generati: {len(expanded_domains)}.", file=sys.stderr)
    
    # 3. Double Check finale (Anti-Sinkholing / WAF Bypass)
    print(f"Avvio la post-validazione (Double Check) su {len(expanded_domains)} domini...", file=sys.stderr)
    
    proxy_list = None
    if getattr(args, 'dns_proxy', None):
        try:
            with open(args.dns_proxy, 'r') as pf:
                proxy_list = [p.strip() for p in pf if p.strip()]
        except Exception as e:
            print(f"  [!] Errore lettura proxy file: {e}", file=sys.stderr)
            
    # Valida usando DoH (se richiesto)
    valid_expanded_domains = dns_manager.double_check(expanded_domains, use_doh=args.use_doh, proxy_list=proxy_list)
    print(f"Double Check terminato. Target considerati sicuri da scansionare: {len(valid_expanded_domains)}.", file=sys.stderr)
    
    return valid_expanded_domains, subdomain_results


def run_infrastructure_analysis_phase(domains: List[str], params: dict, grouped_domains: dict, python_dns_resolvers: list) -> Tuple[List[str], List[dict], dict, dict, dict, dict, dict]:
    """
    Fase 2: Analisi Infrastrutturale.
    Si occupa di recuperare Hosting Provider, ASN, CloudFlare status e IPs originari.
    Filtra inoltre i domini che non superano i check di sicurezza (es. out-of-scope).
    """
    print("\n--- [Fase 2] Infrastructure Analysis Phase ---", file=sys.stderr)
    
    # Analisi Base: WHOIS, ASN, WAF/CDN Detection
    hostingIntel_tool = HostingIntelTool(dns_resolvers=python_dns_resolvers)
    hostingIntel_tool.run(domains, params)
    infra_results = safe_load_json(hostingIntel_tool.get_results())

    # Origin IP Check: Trova i veri IP dietro le CDN
    origin_ip_tool = OriginIpTool(dns_resolvers=python_dns_resolvers)
    origin_ip_tool.run(domains, params, infra_results, grouped_domains=grouped_domains)
    origin_results = safe_load_json(origin_ip_tool.get_results())

    domain_ip_map = infra_results.get('_ip_map', {})
    valid_domains_for_safety = [d for d in domains if "error" not in infra_results.get(d, {})]
    
    # Check di sicurezza: validazione scope / permessi prima dello scanning
    print(f"Esecuzione safety checks su {len(valid_domains_for_safety)} target validi (filtrati {len(domains) - len(valid_domains_for_safety)} errori)...", file=sys.stderr)
    safety_validator = SafetyValidatorTool()
    safety_params = {
        'infrastructure_data': infra_results,
        'domain_ip_map': domain_ip_map
    }
    safety_validator.run(valid_domains_for_safety, safety_params)
    safety_results = safe_load_json(safety_validator.get_results())
    
    safe_targets = []
    skipped_targets = []
    target_params = {}
    
    # Filtriamo cosa processare effettivamente nelle fasi di network
    for domain in domains:
        if "error" in infra_results.get(domain, {}):
            skipped_targets.append({
                'target': domain,
                'reasons': [f"Infrastructure Error: {infra_results[domain]['error']}"],
                'warnings': []
            })
            continue

        safety = safety_results.get(domain, {})
        # Skippa se il tool di validazione reputa il dominio non sicuro da scan (fuori perimetro / CDN protetto restrittivo)
        if not safety.get('is_safe_to_scan', False):
            skipped_targets.append({
                'target': domain,
                'reasons': safety.get('skip_reasons', []),
                'warnings': safety.get('warnings', [])
            })
            continue
        
        target_params[domain] = safety.get('scan_params', {})
        safe_targets.append(domain)
    
    return safe_targets, skipped_targets, target_params, infra_results, origin_results, safety_results, domain_ip_map


def run_port_scanning_phase(safe_targets: List[str], domain_ip_map: dict, params: dict) -> Tuple[dict, set]:
    """
    Fase 3: Scansione Rete e Porte (Nmap).
    Effettua l'attività deduttiva sugli IP e passa ad NMAP la scoperta di eventuali porte Web.
    """
    print("\n--- [Fase 3] Port Scanning Phase ---", file=sys.stderr)
    
    # Deduplicazione a livello IP per risparmiare tempo in nmap (non passare la stessa CDN n volte)
    unique_ips_for_nmap = set()
    ip_to_domains = {}  # Per ritornellare dall'IP scannerizzato ai N target virtuali sopra
    
    for domain in safe_targets:
        ip = domain_ip_map.get(domain)
        if ip:
            unique_ips_for_nmap.add(ip)
            if ip not in ip_to_domains:
                ip_to_domains[ip] = []
            ip_to_domains[ip].append(domain)
        else:
            print(f"ATTENZIONE: Nessun IP trovato in mappa per {domain}, il target verrà ignorato dalla scansione porte.", file=sys.stderr)

    print(f"Nmap deduplication recap: {len(safe_targets)} domini ridotti a {len(unique_ips_for_nmap)} IP unici.", file=sys.stderr)

    nmap_tool = NmapTool()
    nmap_tool.run(list(unique_ips_for_nmap), params)
    nmap_results = safe_load_json(nmap_tool.get_results())
    
    # Identifica porte tipicamente Web (80, 443, ecc.)
    web_targets = set()
    for nmap_ip, data in nmap_results.items():
        if "error" in data:
            continue
        if "tcp" in data:
            for port, service_info in data["tcp"].items():
                state = service_info.get("state")
                name = service_info.get("name", "").lower()
                
                # Se aperta (o filtrata ma potenzialmente aperta) e identificata come web service
                if state in ["open", "filtered", "open|filtered"]:
                    is_web_service = "http" in name or "https" in name or "ssl" in name or port in [80, 443, 8080, 8443]
                    if is_web_service:
                        # Ricostruiamo gli URI associando la porta IP al dominio originario
                        associated_domains = ip_to_domains.get(nmap_ip, [])
                        for original_domain in associated_domains:
                            url = f"{original_domain}:{port}"
                            web_targets.add(url)
                            
    return nmap_results, web_targets


def run_web_recon_phase(web_targets: set, params: dict, target_params: dict, args: argparse.Namespace) -> Tuple[dict, List[str], dict]:
    """
    Fase 4: Ricognizione Web (Httpx & Nuclei).
    Verifica quali URL delle porte esposte tramite NMAP rispondono effettivamente in formato HTTP/S.
    Esegue fingerprint tecnologico e Vulnerability Scanning rapido.
    """
    print(f"\n--- [Fase 4] Web Recon Phase ({len(web_targets)} web targets) ---", file=sys.stderr)
    if not web_targets:
        print("Nessun target web trovato per scansione HTTPX e Nuclei.", file=sys.stderr)
        return {}, [], {}
        
    # Httpx fa l'enrichment e controlla il Live Status
    httpx_tool = HttpxTool()
    httpx_tool.run(list(web_targets), params, target_params=target_params)
    httpx_results = safe_load_json(httpx_tool.get_results())

    # Ricrea l'array di soli domini in vita
    alive_web_targets = []
    for url, data in httpx_results.items():
        if "error" not in data:
             alive_web_targets.append(url)

    # Nuclei sfrutta i target vivi per Vulnerability Scanning
    nuclei_results = {}
    if alive_web_targets:
        skip_nuclei = args.skip_nuclei or params.get('skip_nuclei') or params.get('skip-nuclei')
        if not skip_nuclei:
            print(f"Avvio Advanced Fingerprinting con Nuclei su {len(alive_web_targets)} target web vivi...", file=sys.stderr)
            nuclei_tool = NucleiTool()
            nuclei_tool.run(alive_web_targets, params, target_params=target_params)
            nuclei_results = safe_load_json(nuclei_tool.get_results())
        else:
            print("    [!] Salto Advanced Fingerprinting (Nuclei) come richiesto da parametro/flag.", file=sys.stderr)
             
    return httpx_results, alive_web_targets, nuclei_results


def run_content_discovery_phase(alive_web_targets: List[str], httpx_results: dict, params: dict, target_params: dict, args: argparse.Namespace) -> Tuple[dict, dict, dict]:
    """
    Fase 5: Content Discovery & JS Analysis.
    Usa Katana per spiderare le pagine, JSLuice per estrarre endpoints dai Javascript
    e Ffuf per fuzzing su directory specifiche usando le path raccolte come base dinamica.
    """
    print(f"\n--- [Fase 5] Content Discovery Phase ({len(alive_web_targets)} alive targets) ---", file=sys.stderr)
    spider_results = {}
    js_results = {}
    c_discovery_results = {}
    dynamic_wordlists = {}        # Struttura per passare risultati dinamici al Fuzzer
    all_js_files_with_context = [] # Tiene traccia di chi referenzia il file JS

    if not alive_web_targets:
        return spider_results, js_results, c_discovery_results

    # 1. Web Spidering (Katana)
    spider_tool = SpiderTool()
    spider_tool.run(alive_web_targets, params, target_params=target_params)
    spider_results = safe_load_json(spider_tool.get_results())
    
    # --- OTTIMIZZAZIONE: Batch Validation ---
    # Raccogliamo TUTTI gli URL da validare in un unico colpo per minimizzare l'overhead di httpx
    urls_to_verify = []
    for url, findings in spider_results.items():
        if "error" not in findings:
            urls_to_verify.extend(findings.get("endpoints", []))
            urls_to_verify.extend(findings.get("js_files", []))

    validator = HttpxTool()
    print(f"Validazione batch di {len(urls_to_verify)} URL trovati dallo spider...", file=sys.stderr)
    verified_urls = validator.verify_urls(urls_to_verify)
    
    # Helper per match robusto (ignora trailing slash, case, e porte default)
    def normalize_url(u):
        if not u: return ""
        u = u.lower().rstrip('/')
        if u.startswith('http://') and ':80' in u: u = u.replace(':80', '')
        if u.startswith('https://') and ':443' in u: u = u.replace(':443', '')
        return u

    verified_pool_norm = {normalize_url(u) for u in verified_urls}
    
    for url, findings in spider_results.items():
        domain_key = findings.get("base_domain") or get_hostname_from_url(url)
        if "error" not in findings:
             # Wordlist dinamica per FFUF (Sempre raw/completa)
             if domain_key not in dynamic_wordlists: dynamic_wordlists[domain_key] = set()
             dynamic_wordlists[domain_key].update(findings.get("paths_wordlist", []))
             
             # Report: Filtriamo gli endpoint e i JS usando il pool validato
             if findings.get("endpoints"):
                  validated_eps = [ep for ep in findings["endpoints"] if normalize_url(ep) in verified_pool_norm]
                  spider_results[url]["validated_endpoints"] = validated_eps
                  spider_results[url]["validated_endpoints_count"] = len(validated_eps)

             if findings.get("js_files"):
                  validated_js = [js for js in findings["js_files"] if normalize_url(js) in verified_pool_norm]
                  spider_results[url]["js_files"] = validated_js
                  spider_results[url]["js_files_count"] = len(validated_js)
                  
                  # Segnalibro per JS Analysis (usiamo la lista RAW)
                  for js in findings.get("raw_js_files", []):
                       all_js_files_with_context.append({"url": js, "origin_domain": domain_key})

    # 2. JS Analysis (Jsluice)
    if all_js_files_with_context:
        unique_js_urls = list(set([x["url"] for x in all_js_files_with_context]))
        js_analyzer = JsAnalyzerTool()
        js_analyzer.run(unique_js_urls, params)
        raw_js_results = safe_load_json(js_analyzer.get_results())
        
        temp_js_endpoints = {}
        for context in all_js_files_with_context:
            js_url = context["url"]
            origin_domain = context["origin_domain"]
            js_hosted_domain = get_hostname_from_url(js_url)
            if js_hosted_domain and js_hosted_domain in raw_js_results:
                 if origin_domain not in temp_js_endpoints: temp_js_endpoints[origin_domain] = set()
                 temp_js_endpoints[origin_domain].update(raw_js_results[js_hosted_domain])

        # Batch validation per i risultati di JS Analysis
        js_urls_to_verify = []
        js_mapping = {} # URL -> (domain, original_path)
        for dom, paths in temp_js_endpoints.items():
            base_url = next((u for u in alive_web_targets if dom in u), f"https://{dom}")
            for p in paths:
                full_url = p if p.startswith('http') else f"{base_url.rstrip('/')}/{p.lstrip('/')}"
                js_urls_to_verify.append(full_url)
                js_mapping[full_url] = (dom, p)
        
        print(f"[Phase 5] Validazione batch di {len(js_urls_to_verify)} endpoint estratti dai JS...", file=sys.stderr)
        verified_js_urls = validator.verify_urls(js_urls_to_verify)
        verified_js_pool_norm = {normalize_url(u) for u in verified_js_urls}
        
        # Mappatura inversa robusta
        norm_to_orig = {normalize_url(u): u for u in js_urls_to_verify}

        for vurl_norm in verified_js_pool_norm:
            if vurl_norm in norm_to_orig:
                full_vurl = norm_to_orig[vurl_norm]
                dom, original_p = js_mapping[full_vurl]
                
                if dom not in js_results: js_results[dom] = {"endpoints": set()}
                p_url = urlparse(full_vurl)
                res_path = p_url.path
                if p_url.query: res_path += f"?{p_url.query}"
                js_results[dom]["endpoints"].add(res_path)

        # Finalize JS results counts and wordlists
        for dom, data in js_results.items():
            data["endpoints"] = list(data["endpoints"])
            data["total_extracted_endpoints"] = len(data["endpoints"])
            if dom not in dynamic_wordlists: dynamic_wordlists[dom] = set()
            dynamic_wordlists[dom].update(data["endpoints"])

    # Serializzazione FFUF
    for k in dynamic_wordlists:
         dynamic_wordlists[k] = list(dynamic_wordlists[k])

    # 3. Active Fuzzing con FFUF arricchito dai dati statici
    skip_content_discovery = args.skip_content_discovery or params.get('skip_content_discovery') or params.get('skip-content-discovery')
    if not skip_content_discovery:
        c_discovery_tool = ContentDiscoveryTool()
        c_discovery_tool.run(alive_web_targets, params, httpx_results=httpx_results, target_params=target_params, dynamic_wordlists=dynamic_wordlists)
        c_discovery_results = safe_load_json(c_discovery_tool.get_results())
    else:
        print("    [!] Salto Content Discovery (FFUF) come richiesto da parametro/flag.", file=sys.stderr)

    return spider_results, js_results, c_discovery_results


def run_final_enumeration_phase(web_targets: set, origin_results: dict, grouped_domains: dict, domain_ip_map: dict, python_dns_resolvers: list, params: dict, target_params: dict) -> dict:
    """
    Fase 6: Enumerazione Finale e VHost Scan.
    Incrocia i dati dell'Host con i risultati origin_ip per trovare server protetti dietro proxy.
    """
    print(f"\n--- [Fase 6] Final Enumeration Phase (VHost su {len(web_targets)} targets) ---", file=sys.stderr)
    if not web_targets:
        return {}
        
    # Costruiamo il reverse proxy pattern mapping (Target -> Base)
    domain_to_base = {}
    for base, subs in grouped_domains.items():
        for sub in subs:
            domain_to_base[sub] = base
        domain_to_base[base] = base

    # VHost Enumeration
    vhost_tool = VhostEnumTool(dns_resolvers=python_dns_resolvers)
    vhost_tool.run(list(web_targets), params, target_params=target_params, origin_results=origin_results, domain_to_base=domain_to_base, domain_ip_map=domain_ip_map)
    return safe_load_json(vhost_tool.get_results())

# ==========================================
# MAIN ROUTINE
# ==========================================

def main():
    """
    Punto di ingresso che orchestra in ordine tutte le fasi di un ASM.
    Raccoglie le statistiche in background e stampa i risultati sottoforma di oggetto JSON
    composto agganciandosi alla standard out (stdout).
    """
    start_time = datetime.now()
    phase_timings = {}
    
    # ----------------------------------------------------
    #  A. SETUP AMBIENTE E PARSING INGRESSO
    # ----------------------------------------------------
    parser = argparse.ArgumentParser(description='ASM - Modulo di recon attiva')
    parser.add_argument('--input', type=str, help='JSON input string', required=False)
    parser.add_argument('--file', type=str, help='Path to JSON input file', required=False)
    parser.add_argument('--use-doh', action='store_true', help='Use DNS-over-HTTPS for final validation')
    parser.add_argument('--dns-proxy', type=str, help='Path to a txt file containing a list of proxies (HTTP/SOCKS5) for DoH')
    parser.add_argument('--output-dir', type=str, help='Output directory for scan results (default: results/).', default=None)
    
    # Flags for JSON parameter overrides
    parser.add_argument('--scan-type', type=str, choices=['fast', 'accurate', 'comprehensive', 'stealth'], help='Scan aggressiveness profile')
    parser.add_argument('--max-depth', type=int, help='Maximum subdomain enumeration depth')
    parser.add_argument('--smart', action='store_true', default=None, help='Enable smart permutations')
    parser.add_argument('--no-smart', action='store_false', dest='smart', help='Disable smart permutations')
    parser.add_argument('--max-wildcards', type=int, help='AlterX wildcard variable limit')
    parser.add_argument('--timing', type=str, choices=['normal', 'polite'], help='Nmap timing profile')
    parser.add_argument('--max-rate', type=int, help='Packet rate limit (Nmap/Nuclei)')
    parser.add_argument('--skip-content-discovery', action='store_true', default=None, help='Skip content discovery phase')
    parser.add_argument('--no-skip-content-discovery', action='store_false', dest='skip_content_discovery', help='Force content discovery execution')
    parser.add_argument('--skip-nuclei', action='store_true', default=None, help='Skip Nuclei scanning phase')
    parser.add_argument('--no-skip-nuclei', action='store_false', dest='skip_nuclei', help='Force Nuclei execution')
    parser.add_argument('--recursion-depth', type=int, help='FFUF recursion depth')
    parser.add_argument('--subdomains-wordlist', type=str, help='Subdomain enumeration wordlist')
    parser.add_argument('--permutations-wordlist', type=str, help='AlterX permutations wordlist')
    parser.add_argument('--vhost-wordlist', type=str, help='VHost enumeration wordlist')
    
    # Rotation Monitor flags
    parser.add_argument('--rotation-enabled', action='store_true', default=None, help='Enable IP rotation monitor')
    parser.add_argument('--rotation-disabled', action='store_false', dest='rotation_enabled', help='Disable IP rotation monitor')
    parser.add_argument('--rotation-interval', type=int, help='IP monitoring interval (sec)')
    parser.add_argument('--rotation-duration', type=int, help='IP monitoring duration (sec)')
    
    args = parser.parse_args()

    # Logica recupero ingresso
    data = None
    if args.input:
        try:
            data = json.loads(args.input)
        except json.JSONDecodeError as e:
            print(f"Errore nella decodifica del JSON di input: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Errore nella lettura del file di input: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if not sys.stdin.isatty():
            try:
                content = sys.stdin.read()
                if content:
                    data = json.loads(content)
            except Exception as e:
                print(f"Errore nella lettura da stdin: {e}", file=sys.stderr)
                sys.exit(1)
    
    if data is None:
        parser.print_help()
        sys.exit(1)

    domains = data.get('target_list', [])
    params = data.get('params', {})
    passive_subdomains = data.get('passive_subdomains', {})

    # Merging CLI arguments into params (CLI has precedence)
    cli_params_map = {
        'scan_type': args.scan_type,
        'max_depth': args.max_depth,
        'smart': args.smart,
        'max_wildcards': args.max_wildcards,
        'timing': args.timing,
        'max_rate': args.max_rate,
        'skip_content_discovery': args.skip_content_discovery,
        'skip_nuclei': args.skip_nuclei,
        'recursion_depth': args.recursion_depth,
        'subdomains_wordlist': args.subdomains_wordlist,
        'permutations_wordlist': args.permutations_wordlist,
        'vhost_wordlist': args.vhost_wordlist
    }
    
    for key, value in cli_params_map.items():
        if value is not None:
            params[key] = value
            
    # Maneggio speciale per rotation_monitor (oggetto annidato)
    if args.rotation_enabled is not None or args.rotation_interval is not None or args.rotation_duration is not None:
        if 'rotation_monitor' not in params:
            params['rotation_monitor'] = {}
        
        if args.rotation_enabled is not None:
            params['rotation_monitor']['enabled'] = args.rotation_enabled
        if args.rotation_interval is not None:
            params['rotation_monitor']['interval_seconds'] = args.rotation_interval
        if args.rotation_duration is not None:
            params['rotation_monitor']['duration_seconds'] = args.rotation_duration

    if not domains:
        print("Errore: Nessun dominio specificato nell'input.", file=sys.stderr)
        sys.exit(1)

    # Creazione cartella di output per questa run
    scan_dir = setup_scan_directory(start_time, params, args)
    print(f"Scan directory: {scan_dir}", file=sys.stderr)

    # Avvio cattura stderr su file
    stderr_log_path = os.path.join(scan_dir, "stderr.log")
    _stderr_log_file = open(stderr_log_path, 'w')
    _original_stderr = sys.stderr
    sys.stderr = TeeStream(_original_stderr, _stderr_log_file)

    # Salva debug info (subito, prima che la scansione parta)
    save_debug_info(scan_dir, args, params, domains, start_time)

    # Inizializzatore DNS Pool Manager
    dns_manager = DnsManagerTool()
    python_dns_resolvers = dns_manager.get_resolvers(max_count=50)

    # ----------------------------------------------------
    #  B. ESECUZIONE FASI ATTIVE E PASSIVE (PIPELINE)
    # ----------------------------------------------------

    # ==== FASE 1: Subdomain Enumeration ====
    t1_start = time.time()
    domains, subdomain_results = run_subdomain_enumeration_phase(
        domains, passive_subdomains, params, args, dns_manager, python_dns_resolvers
    )
    phase_timings["subdomain_enumeration"] = round(time.time() - t1_start, 2)
    
    grouped_domains = group_domains_by_base(domains)

    # ==== FASE 2: Analisi Infrastruttura (Host Intel, WAF, Safety) ====
    t2_start = time.time()
    safe_targets, skipped_targets, target_params, infra_results, origin_results, safety_results, domain_ip_map = run_infrastructure_analysis_phase(
        domains, params, grouped_domains, python_dns_resolvers
    )
    phase_timings["infrastructure_analysis"] = round(time.time() - t2_start, 2)

    if skipped_targets:
        print(f"\nSkipped {len(skipped_targets)} target(s):", file=sys.stderr)
        for skip in skipped_targets:
            reasons = ', '.join(skip['reasons'])
            print(f"  - {skip['target']}: {reasons}", file=sys.stderr)
            
    # Exit Anticipato in sicurezza se il perimetro di attacco si azzera
    if not safe_targets:
        print("\nNessun target sicuro da scansionare.", file=sys.stderr)
        final_results = {}
        for skip in skipped_targets:
            final_results[skip['target']] = {
                'skipped': True,
                'reasons': skip['reasons'],
                'infrastructure': infra_results.get(skip['target'], {}),
                'safety_check': safety_results.get(skip['target'], {})
            }
        print(json.dumps(final_results, indent=4))
        sys.exit(0)

    print(f"Proceeding with {len(safe_targets)} safe target(s)", file=sys.stderr)

    # Iniezione background tool (IP Rotation) post cleaning WAF 
    # Analizza i cambiamenti live del dns su quei dati mentre i sub-tool fanno scansioni lorde in foreground
    iprotation_monitor = IPRotationTool(dns_resolvers=python_dns_resolvers)
    iprotation_monitor.run(safe_targets, params)

    # ==== FASE 3: Port Scanning (Network Recon) ====
    t3_start = time.time()
    nmap_results, web_targets = run_port_scanning_phase(safe_targets, domain_ip_map, params)
    phase_timings["port_scanning"] = round(time.time() - t3_start, 2)

    # ==== FASE 4: Live Web Recon & Fingerprinting (Nuclei/Httpx) ====
    t4_start = time.time()
    httpx_results, alive_web_targets, nuclei_results = run_web_recon_phase(web_targets, params, target_params, args)
    phase_timings["web_recon"] = round(time.time() - t4_start, 2)

    # ==== FASE 5: Content Discovery & App layer analysis (Katana/Jsluice/Ffuf) ====
    t5_start = time.time()
    spider_results, js_results, c_discovery_results = run_content_discovery_phase(
        alive_web_targets, httpx_results, params, target_params, args
    )
    phase_timings["content_discovery"] = round(time.time() - t5_start, 2)

    # ==== FASE 6: Virtual Hosts Enumeration (Nascosti su reverse proxies) ====
    t6_start = time.time()
    vhost_results = run_final_enumeration_phase(
        web_targets, origin_results, grouped_domains, domain_ip_map, python_dns_resolvers, params, target_params
    )
    phase_timings["vhost_enumeration"] = round(time.time() - t6_start, 2)

    # Fine delle scansioni di attacco => Interrompe il worker in Background di rotazione
    iprotation_monitor.stop()
    rotation_results = safe_load_json(iprotation_monitor.get_results())

    # ----------------------------------------------------
    #  C. AGGREGAZIONE DATI E SERIALIZZAZIONE FINALE JSON
    # ----------------------------------------------------
    
    # Questo step condensa le liste disallineate in formato strutturato per singolo origin domain target
    final_results = {}

    # Struttura madre su domini "Safe / Analyzed"
    for domain in safe_targets:
        ip_address = domain_ip_map.get(domain)
        nmap_data = nmap_results.get(ip_address, {}) if ip_address else {}

        domain_result = {
            "ip": ip_address,
            "scan_type": params.get("scan_type", "fast"),
            "infrastructure": infra_results.get(ip_address, infra_results.get(domain, {})),
            "origin_ip_bypass": origin_results.get(domain, {}),
            "safety_check": safety_results.get(domain, {}),
            "scan_params_applied": target_params.get(domain, {}),
            "subdomain_enum": {},
            "ports": [],
            "web_recon": {},
            "spidering": {},
            "js_analysis": {},
            "advanced_fingerprint": [],
            "content_discovery": [],
            "vhost_enum": {},
            "ip_rotation": {}
        }

        # Gestione Nmap
        if "error" in nmap_data:
            domain_result["error"] = nmap_data["error"]
        
        if "tcp" in nmap_data:
            for port, info in nmap_data["tcp"].items():
                domain_result["ports"].append({
                    "port": port,
                    "service": info.get("name", "unknown"),
                    "state": info.get("state", "unknown"),
                    "product": info.get("product", ""),
                    "version": info.get("version", "")
                })
        
        final_results[domain] = domain_result

    # Struttura minimale su domini "Skipped / Invalidated"
    for skip in skipped_targets:
        final_results[skip['target']] = {
            'skipped': True,
            'reasons': skip['reasons'],
            'warnings': skip.get('warnings', []),
            'infrastructure': infra_results.get(skip['target'], {}),
            'safety_check': safety_results.get(skip['target'], {})
        }

    # Assegnazione WebLive e Headers 
    for url, data in httpx_results.items():
        domain_key = get_hostname_from_url(url)
        if domain_key in final_results:
            final_results[domain_key]["web_recon"][url] = data

    # Assegnazione Template vulnerabili e Web Tech
    for url, findings in nuclei_results.items():
        domain_key = get_hostname_from_url(url)
        if domain_key in final_results:
            if "error" in findings:
                final_results[domain_key]["advanced_fingerprint"].append({"error": findings["error"]})
            elif isinstance(findings, list) and len(findings) > 0:
                final_results[domain_key]["advanced_fingerprint"].extend(findings)

    # Assegnazione Spider Endpoints e Files
    for url, findings in spider_results.items():
        domain_key = findings.get("base_domain") or get_hostname_from_url(url)
        if domain_key in final_results:
            # --- Noise Reduction: Rimuovi liste grezze e wordlist chilometriche ---
            findings.pop("paths_wordlist", None)
            findings.pop("raw_js_files", None)
            findings.pop("endpoints", None) # Restano i "validated_endpoints"
            
            final_results[domain_key]["spidering"][url] = findings

    # Assegnazione Secret Detection ed API passiva
    for domain_key, data in js_results.items():
        if domain_key in final_results:
            final_results[domain_key]["js_analysis"] = data

    # Assegnazione Active Directory Bruteforce
    for url, findings in c_discovery_results.items():
        domain_key = get_hostname_from_url(url)
        if domain_key in final_results:
            if "error" in findings:
                final_results[domain_key]["content_discovery"].append({"error": findings["error"]})
            elif isinstance(findings, list) and len(findings) > 0:
                final_results[domain_key]["content_discovery"].extend(findings)

    # Assegnazione VirtualHost Mismatch
    for url, vhost_data in vhost_results.items():
        base_domain = url.split(':')[0].replace('http://', '').replace('https://', '')
        if base_domain in final_results:
            final_results[base_domain]["vhost_enum"][url] = vhost_data

    # Assegnazione Dynamic Background Monitoring Data
    for domain, rotation_data in rotation_results.items():
        if domain in final_results:
            final_results[domain]["ip_rotation"] = rotation_data

    # Assegnazione Subdomains iniziali per riferimento root
    # Garantiamo che il seed esista nel JSON anche se è stato scartato dalla pipeline (es. per WAF)
    for seed, result in subdomain_results.items():
        if seed not in final_results:
            final_results[seed] = {
                "skipped": True,
                "reasons": ["Seed ignorato dalla scansione attiva (es. failed DNS o WAF). Sottodomini esplorati ugualmente."],
                "subdomain_enum": {}
            }
        final_results[seed]["subdomain_enum"] = result

    # Calcolo durata totale
    end_time = datetime.now()
    duration = end_time - start_time
    duration_str = str(duration).split('.')[0] # Formato HH:MM:SS

    # Creazione struttura finale globale 
    global_results = {
        "scan_start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_duration": duration_str,
        "phase_timings": phase_timings,
        "scan_parameters": params,
        "arguments": vars(args),
        "targets": final_results
    }

    # Emit JSON Output in stdout
    json_output = json.dumps(global_results, indent=4)
    print(json_output)
    
    # Salvataggio results.json nella cartella della run con nome conforme alla richiesta
    filename = f"{os.path.basename(scan_dir)}.json"
    results_filepath = os.path.join(scan_dir, filename)
    try:
        with open(results_filepath, 'w') as f:
            f.write(json_output)
        print(f"\nRisultati salvati con successo in: {results_filepath}", file=sys.stderr)
    except Exception as e:
        print(f"\nErrore durante il salvataggio del file: {e}", file=sys.stderr)

    # Salva stdout (il JSON) anche come file separato per completezza
    stdout_filepath = os.path.join(scan_dir, "stdout.log")
    try:
        with open(stdout_filepath, 'w') as f:
            f.write(json_output + '\n')
    except Exception:
        pass

    # Chiudi il tee di stderr e ripristina lo stream originale
    print(f"Scan completato. Tutti i file della run sono in: {scan_dir}", file=sys.stderr)
    sys.stderr = _original_stderr
    try:
        _stderr_log_file.close()
    except Exception:
        pass

# Esecuzione modulo in stand-alone
if __name__ == "__main__":
    main()
