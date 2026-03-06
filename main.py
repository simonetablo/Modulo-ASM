import json
import argparse
import sys
import os
from datetime import datetime
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

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

def safe_load_json(data_str: str) -> dict:
    """Helper robusto per il parsing sicuro dell'output dei tool in formato JSON."""
    try:
        if not data_str or not data_str.strip():
            return {}
        return json.loads(data_str)
    except Exception as e:
        print(f"ATTENZIONE: JSON parser error ({e}) on tool output. Fallback to {{}}.", file=sys.stderr)
        return {}

def group_domains_by_base(domains: List[str]) -> Dict[str, List[str]]:
    """
    Raggruppa una lista di domini in base alla loro root (dominio base).
    (es. api.azienda.com -> azienda.com)
    Utile per gli strumenti che operano a livello di dominio base (come origin_ip_tool e vhost_enum_tool).
    """
    groups = {}
    for d in domains:
        parts = d.split('.')
        if len(parts) >= 2:
            base = f"{parts[-2]}.{parts[-1]}"
        else:
            base = d
            
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
        if not args.skip_nuclei:
            print(f"Avvio Advanced Fingerprinting con Nuclei su {len(alive_web_targets)} target web vivi...", file=sys.stderr)
            nuclei_tool = NucleiTool()
            nuclei_tool.run(alive_web_targets, params, target_params=target_params)
            nuclei_results = safe_load_json(nuclei_tool.get_results())
        else:
            print("    [!] Salto Advanced Fingerprinting (Nuclei) come richiesto da flag.", file=sys.stderr)
             
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

    # 1. Web Spidering (Katana) per endpoint e file JS passivi
    spider_tool = SpiderTool()
    spider_tool.run(alive_web_targets, params, target_params=target_params)
    spider_results = safe_load_json(spider_tool.get_results())
    
    for url, findings in spider_results.items():
        domain_key = findings.get("base_domain") or get_hostname_from_url(url)
            
        if "error" not in findings:
             # Popolamento Wordlist dinamica (per FFUF) con query/paths dallo spider
             if domain_key not in dynamic_wordlists:
                  dynamic_wordlists[domain_key] = set()
             if findings.get("paths_wordlist"):
                  dynamic_wordlists[domain_key].update(findings["paths_wordlist"])
             
             # Segnalibro dei JS files da analizzare
             if findings.get("js_files"):
                  for js in findings["js_files"]:
                       all_js_files_with_context.append({"url": js, "origin_domain": domain_key})

    # 2. JS Analysis (Jsluice)
    if all_js_files_with_context:
        unique_js_urls = list(set([x["url"] for x in all_js_files_with_context]))
        js_analyzer = JsAnalyzerTool()
        js_analyzer.run(unique_js_urls, params)
        raw_js_results = safe_load_json(js_analyzer.get_results())
        
        # Riappropriazione dei findings basata sull'origin domain
        # Jsluice manderà il dom della CDN, ma noi lo mappiamo a chi lo ha richiesto
        for context in all_js_files_with_context:
            js_url = context["url"]
            origin_domain = context["origin_domain"]
            
            js_hosted_domain = get_hostname_from_url(js_url)
            if js_hosted_domain and js_hosted_domain in raw_js_results:
                 extracted_paths = raw_js_results[js_hosted_domain]
                 
                 # Mappa ad origin root json
                 if origin_domain not in js_results:
                     js_results[origin_domain] = {"endpoints": set()}
                 js_results[origin_domain]["endpoints"].update(extracted_paths)
                 
                 # Mappa ad FFUF list
                 if origin_domain not in dynamic_wordlists:
                      dynamic_wordlists[origin_domain] = set()
                 dynamic_wordlists[origin_domain].update(extracted_paths)

    # Convert sets to list for FFUF serialization
    for k in dynamic_wordlists:
         dynamic_wordlists[k] = list(dynamic_wordlists[k])
         
    for dom in js_results:
        js_results[dom]["endpoints"] = list(js_results[dom]["endpoints"])
        js_results[dom]["total_extracted_endpoints"] = len(js_results[dom]["endpoints"])

    # 3. Active Fuzzing con FFUF arricchito dai dati statici
    if not args.skip_content_discovery:
        c_discovery_tool = ContentDiscoveryTool()
        c_discovery_tool.run(alive_web_targets, params, httpx_results=httpx_results, target_params=target_params, dynamic_wordlists=dynamic_wordlists)
        c_discovery_results = safe_load_json(c_discovery_tool.get_results())
    else:
        print("    [!] Salto Content Discovery (FFUF) come richiesto da flag.", file=sys.stderr)

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
    
    # ----------------------------------------------------
    #  A. SETUP AMBIENTE E PARSING INGRESSO
    # ----------------------------------------------------
    parser = argparse.ArgumentParser(description='ASM Module Backend - Modulo di scansione')
    parser.add_argument('--input', type=str, help='Stringa JSON di input', required=False)
    parser.add_argument('--file', type=str, help='Percorso al file JSON di input', required=False)
    parser.add_argument('--use-doh', action='store_true', help='Utilizza DNS-over-HTTPS per validazione finale')
    parser.add_argument('--dns-proxy', type=str, help='Percorso a un file txt contenente una lista di proxy (HTTP/SOCKS5) da usare per DoH')
    parser.add_argument('--skip-content-discovery', action='store_true', help='Salta la fase attiva di Fuzzing (Content Discovery) mantenendo lo spidering passivo.')
    parser.add_argument('--skip-nuclei', action='store_true', help='Salta la fase di Advanced Fingerprinting (Nuclei).')
    parser.add_argument('--output-dir', type=str, help='Directory di destinazione per salvare il JSON finale (default: cartella corrente).', default='.')
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

    if not domains:
        print("Errore: Nessun dominio specificato nell'input.", file=sys.stderr)
        sys.exit(1)

    # Inizializzatore DNS Pool Manager
    dns_manager = DnsManagerTool()
    python_dns_resolvers = dns_manager.get_resolvers(max_count=50)

    # ----------------------------------------------------
    #  B. ESECUZIONE FASI ATTIVE E PASSIVE (PIPELINE)
    # ----------------------------------------------------

    # ==== FASE 1: Subdomain Enumeration ====
    domains, subdomain_results = run_subdomain_enumeration_phase(
        domains, passive_subdomains, params, args, dns_manager, python_dns_resolvers
    )
    grouped_domains = group_domains_by_base(domains)

    # ==== FASE 2: Analisi Infrastruttura (Host Intel, WAF, Safety) ====
    safe_targets, skipped_targets, target_params, infra_results, origin_results, safety_results, domain_ip_map = run_infrastructure_analysis_phase(
        domains, params, grouped_domains, python_dns_resolvers
    )

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

    print(f"\nProceeding with {len(safe_targets)} safe target(s)", file=sys.stderr)

    # Iniezione background tool (IP Rotation) post cleaning WAF 
    # Analizza i cambiamenti live del dns su quei dati mentre i sub-tool fanno scansioni lorde in foreground
    iprotation_monitor = IPRotationTool(dns_resolvers=python_dns_resolvers)
    iprotation_monitor.start_monitoring(safe_targets, interval=10, duration=30)

    # ==== FASE 3: Port Scanning (Network Recon) ====
    nmap_results, web_targets = run_port_scanning_phase(safe_targets, domain_ip_map, params)

    # ==== FASE 4: Live Web Recon & Fingerprinting (Nuclei/Httpx) ====
    httpx_results, alive_web_targets, nuclei_results = run_web_recon_phase(web_targets, params, target_params, args)

    # ==== FASE 5: Content Discovery & App layer analysis (Katana/Jsluice/Ffuf) ====
    spider_results, js_results, c_discovery_results = run_content_discovery_phase(
        alive_web_targets, httpx_results, params, target_params, args
    )

    # ==== FASE 6: Virtual Hosts Enumeration (Nascosti su reverse proxies) ====
    vhost_results = run_final_enumeration_phase(
        web_targets, origin_results, grouped_domains, domain_ip_map, python_dns_resolvers, params, target_params
    )

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
        "scan_parameters": params,
        "arguments": vars(args),
        "targets": final_results
    }

    # Emit JSON Output in stdout
    json_output = json.dumps(global_results, indent=4)
    print(json_output)
    
    # Salvataggio su file con timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"asm_results_{timestamp}.json"
    
    # Assicurati che la directory esista
    output_dir = args.output_dir
    if output_dir != '.' and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            print(f"  [!] Errore nella creazione della directory {output_dir}: {e}. Salvo in cartella corrente.", file=sys.stderr)
            output_dir = '.'
            
    filepath = os.path.join(output_dir, filename)
    
    try:
        with open(filepath, 'w') as f:
            f.write(json_output)
        print(f"\nRisultati salvati con successo in: {filepath}", file=sys.stderr)
    except Exception as e:
        print(f"\nErrore durante il salvataggio del file: {e}", file=sys.stderr)

# Esecuzione modulo in stand-alone
if __name__ == "__main__":
    main()
