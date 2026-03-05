import json
import argparse
import sys
from typing import List, Dict, Any
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
    """Helper robusto per il parsing sicuro dell'output dei tool."""
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

def main():
    """
    Punto di ingresso principale del modulo ASM.
    
    Questa funzione si occupa di:
    1. Parsing degli argomenti da riga di comando.
    2. Lettura dell'input (JSON) da file, stringa o stdin.
    3. Inizializzazione dei tool necessari (es. NmapTool).
    4. Esecuzione della scansione.
    5. Stampa dei risultati in formato JSON su stdout.
    """
    
    # Configurazione del parser degli argomenti
    parser = argparse.ArgumentParser(description='ASM Module Backend - Modulo di scansione')
    parser.add_argument('--input', type=str, help='Stringa JSON di input', required=False)
    parser.add_argument('--file', type=str, help='Percorso al file JSON di input', required=False)
    parser.add_argument('--use-doh', action='store_true', help='Utilizza DNS-over-HTTPS per validazione finale (Lento ma utile per ruotare proxy o non usare UDP)')
    parser.add_argument('--dns-proxy', type=str, help='Percorso a un file txt contenente una lista di proxy (HTTP/SOCKS5) da usare per DoH')

    args = parser.parse_args()

    data = None
    
    # Logica per determinare la sorgente dell'input
    if args.input:
        # Caso 1: Input passato direttamente come stringa JSON via argomento --input
        try:
            data = json.loads(args.input)
        except json.JSONDecodeError as e:
            print(f"Errore nella decodifica del JSON di input: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.file:
        # Caso 2: Input letto da un file specificato via --file
        try:
            with open(args.file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Errore nella lettura del file di input: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Caso 3: Input letto dallo Standard Input (stdin)
        # Utile per il piping
        if not sys.stdin.isatty():
            try:
                content = sys.stdin.read()
                if content:
                    data = json.loads(content)
            except Exception as e:
                print(f"Errore nella lettura da stdin: {e}", file=sys.stderr)
                sys.exit(1)
    
    # Se nessun dato valido è stato caricato, stampa l'help ed esce
    if data is None:
        parser.print_help()
        sys.exit(1)

    # Estrazione dei domini e dei parametri dal JSON
    domains = data.get('target_list', [])
    params = data.get('params', {})
    passive_subdomains = data.get('passive_subdomains', {})

    if not domains:
        print("Errore: Nessun dominio specificato nell'input.", file=sys.stderr)
        sys.exit(1)

    # Gestione centralizzata dei DNS Resolver
    dns_manager = DnsManagerTool()
    # Puredns e tool asincroni in Go possono gestire agevolmente migliaia di resolver
    all_dns_resolvers = dns_manager.get_resolvers(max_count=0)
    # I tool basati su librerie Python native (dns.resolver) lavorano meglio a batch più piccoli
    python_dns_resolvers = dns_manager.get_resolvers(max_count=50)

    # Step 1: Subdomain Enumeration (Active)
    # Eseguita come primo step per espandere la superficie di attacco
    # Da notare: passiamo tutti i resolver (all_dns_resolvers) per massimizzare la velocità
    subdomain_tool = SubdomainEnumTool(dns_resolvers=all_dns_resolvers)
    subdomain_tool.run(domains, params)
    subdomain_results_json = subdomain_tool.get_results()
    subdomain_results = safe_load_json(subdomain_results_json)
    
    # Espande la lista dei domini con quelli trovati
    discovered_domains = set(domains) # Include i semi originali
    for seed, result in subdomain_results.items():
        if "discovered_subdomains" in result:
            discovered_domains.update(result["discovered_subdomains"])
    
    # --- Step 1.1: Permutation Scanning (AlterX + PureDNS Resolve) ---
    # Genera variazioni dei domini scoperti e le valida.

    # Passiamo opzioni per limitare le permutazioni
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
             
        # Costruiamo la lista di input per questo seed: il seed stesso, 
        # i sottodomini scoperti via bruteforce E quelli passivi forniti dall'utente
        # Questo garantisce ad AlterX il massimo contesto aziendale.
        group_domains = [seed]
        
        # Aggiungiamo quelli ricavati dalla fase attiva (bruteforce puredns)
        if "discovered_subdomains" in result:
            group_domains.extend(result["discovered_subdomains"])
            
        # Aggiungiamo i passivi passati dall'utente per questo preciso root domain
        passive_for_seed = passive_subdomains.get(seed, [])
        if passive_for_seed:
            group_domains.extend(passive_for_seed)
            
        # Rimuoviamo duplicati per alleggerire AlterX
        group_domains = list(set(group_domains))
            
        # Skip se non ci sono domini sufficienti (almeno 1)
        if not group_domains:
            continue
        
        # Esegui alterx sul gruppo
        permutation_tool.run(group_domains, perm_params_base)
        perm_results = safe_load_json(permutation_tool.get_results())

        # Raccogli candidati per questo gruppo
        candidates = set()

        if perm_results:
            for p_seed, p_res in perm_results.items():
                if "permutations" in p_res:
                    candidates.update(p_res["permutations"])
        
        candidates -= set(discovered_domains) # Rimuovi tutto ciò che è già noto globalmente
        
        if candidates:
            perm_resolve_tool = SubdomainEnumTool(dns_resolvers=python_dns_resolvers)
            perm_resolve_tool.run(list(candidates), {"method": "resolve"})
            resolve_results = safe_load_json(perm_resolve_tool.get_results())
            
            if "resolved_domains" in resolve_results:
                valid = resolve_results["resolved_domains"]["domains"]
                print(f"  [+] {len(valid)} new valid subdomains for {seed}", file=sys.stderr)
                all_valid_permutations.update(valid)
        
    if all_valid_permutations:
        print(f"Permutation Scanning Total: trovati {len(all_valid_permutations)} nuovi sottodomini validi.", file=sys.stderr)
        discovered_domains.update(all_valid_permutations)
    else:
        print("Nessuna nuova permutazione valida trovata.", file=sys.stderr)

    expanded_domains = list(discovered_domains)
    print(f"Subdomain enumeration (Bruteforce + Permutations) completata. Target parzialmente generati: {len(expanded_domains)}.", file=sys.stderr)
    
    # --- Step 1.2: Final DNS Validation (Double Check) ---
    # Rimuoviamo i falsi positivi (sinkholing, poisoned resolvers) validando tutti gli
    # expanded target esclusivamente contro i resolvers "fidati" e "trusted".
    print(f"Avvio la post-validazione (Double Check) su {len(expanded_domains)} domini...", file=sys.stderr)
    
    # Estraiamo la proxy list se passata in input
    proxy_list = None
    if args.dns_proxy:
        try:
            with open(args.dns_proxy, 'r') as pf:
                proxy_list = [p.strip() for p in pf if p.strip()]
        except Exception as e:
            print(f"  [!] Errore lettura proxy file: {e}", file=sys.stderr)
            
    valid_expanded_domains = dns_manager.double_check(expanded_domains, use_doh=args.use_doh, proxy_list=proxy_list)
    print(f"Double Check terminato. Target considerati sicuri da scansionare: {len(valid_expanded_domains)}.", file=sys.stderr)
    
    # Da qui in poi usiamo i domini validati invece dei domini originali
    domains = valid_expanded_domains
    print(f"Domains: {domains}", file=sys.stderr)
    # Calcola il raggruppamento domini centralizzato
    grouped_domains = group_domains_by_base(domains)

    # Analisi infrastrutturale per identificare eventuali CDN/Cloud/IP Dinamici
    hostingIntel_tool = HostingIntelTool(dns_resolvers=python_dns_resolvers)
    hostingIntel_tool.run(domains, params)
    infra_results_json = hostingIntel_tool.get_results()
    infra_results = safe_load_json(infra_results_json)

    # Esegue ricerca Origin IPs
    origin_ip_tool = OriginIpTool(dns_resolvers=python_dns_resolvers)
    origin_ip_tool.run(domains, params, infra_results, grouped_domains=grouped_domains)
    origin_results_json = origin_ip_tool.get_results()
    origin_results = safe_load_json(origin_results_json)

    # Estrae mapping dominio -> IP da HostingIntelTool tramite get invece che pop
    domain_ip_map = infra_results.get('_ip_map', {})

    # Safety Checks per decidere se e come procedere con le scansioni
    # Filtra i domini validi (senza errori infrastrutturali) per il safety check
    valid_domains_for_safety = [d for d in domains if "error" not in infra_results.get(d, {})]
    
    print(f"Esecuzione safety checks su {len(valid_domains_for_safety)} target validi (filtrati {len(domains) - len(valid_domains_for_safety)} errori)...", file=sys.stderr)
    safety_validator = SafetyValidatorTool()
    safety_params = {
        'infrastructure_data': infra_results,
        'domain_ip_map': domain_ip_map
    }
    safety_validator.run(valid_domains_for_safety, safety_params)
    safety_results_json = safety_validator.get_results()
    safety_results = safe_load_json(safety_results_json)
    
    # Filtra target sicuri e skippa quelli non sicuri
    safe_targets = []
    skipped_targets = []
    target_params = {}  # Store per-target scan parameters
    
    for domain in domains:
        # Prima controlla se ci sono stati errori infrastrutturali
        if "error" in infra_results.get(domain, {}):
            skipped_targets.append({
                'target': domain,
                'reasons': [f"Infrastructure Error: {infra_results[domain]['error']}"],
                'warnings': []
            })
            continue

        safety = safety_results.get(domain, {})
        
        if not safety.get('is_safe_to_scan', False):
            skipped_targets.append({
                'target': domain,
                'reasons': safety.get('skip_reasons', []),
                'warnings': safety.get('warnings', [])
            })
            continue
        
        # Store per-target scan parameters
        scan_params = safety.get('scan_params', {})
        target_params[domain] = scan_params
        
        safe_targets.append(domain)
    
    # Log target skippati
    if skipped_targets:
        print(f"\n⚠️  Skipped {len(skipped_targets)} target(s):", file=sys.stderr)
        for skip in skipped_targets:
            reasons = ', '.join(skip['reasons'])
            print(f"  - {skip['target']}: {reasons}", file=sys.stderr)
            
    if not safe_targets:
        print("\n❌ Nessun target sicuro da scansionare.", file=sys.stderr)
        # Restituisci comunque i risultati con info su target skippati
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

    print(f"\n✅ Proceeding with {len(safe_targets)} safe target(s)", file=sys.stderr)

    # Avvio monitoraggio rotazione IP in background
    # Il monitor userà i DNS resolver limitati per Python
    iprotation_monitor = IPRotationTool(dns_resolvers=python_dns_resolvers)
    iprotation_monitor.start_monitoring(safe_targets, interval=10, duration=30)



    # Estrazione IP unici dai safe_targets per nmap (Deduplicazione di Rete)
    unique_ips_for_nmap = set()
    ip_to_domains = {}  # Mappa inversa IP -> lista di domini per riassociare i risultati
    
    for domain in safe_targets:
        ip = domain_ip_map.get(domain)
        if ip:
            unique_ips_for_nmap.add(ip)
            if ip not in ip_to_domains:
                ip_to_domains[ip] = []
            ip_to_domains[ip].append(domain)
        else:
            print(f"ATTENZIONE: Nessun IP trovato in mappa per {domain}, il target verrà ignorato dalla scansione porte.", file=sys.stderr)

    print(f"\n✅ Nmap deduplication recap: {len(safe_targets)} domini ridotti a {len(unique_ips_for_nmap)} IP unici.", file=sys.stderr)

    # Inizializzazione di nmap tool
    nmap_tool = NmapTool()

    # Esecuzione del tool con IP unici deduplicati
    # NOTA: Passiamo params generici perché Nmap qui scansiona IPs, non domini. 
    # I target_params complessi a livello dominio non si applicano direttamente raggruppando per IP.
    nmap_tool.run(list(unique_ips_for_nmap), params)

    
    # Recupero dei risultati di Nmap
    nmap_results_json = nmap_tool.get_results()
    nmap_results = safe_load_json(nmap_results_json)
    
    # Analisi dei risultati per identificare target web (porte 80/443 aperte)
    web_targets = set()
        
    for nmap_ip, data in nmap_results.items():
        # Salta se c'è stato un errore su questo dominio
        if "error" in data:
            continue
            
        # Controllo su tutte le porte TCP aperte per servizi HTTP/HTTPS
        if "tcp" in data:
            for port, service_info in data["tcp"].items():
                state = service_info.get("state")
                name = service_info.get("name", "").lower()
                
                # Considera solo porte aperte o filtrate (che potrebbero essere aperte)
                if state in ["open", "filtered", "open|filtered"]:
                    # Logica per determinare se è un servizio web (http, https, ssl o porte standard)
                    is_web_service = "http" in name or "https" in name or "ssl" in name or port in [80, 443, 8080, 8443]
                            
                    if is_web_service:
                        # Dobbiamo risalire ai domini originali che puntavano a questo IP
                        associated_domains = ip_to_domains.get(nmap_ip, []) # nmap_ip in realtà è un IP

                        for original_domain in associated_domains:
                            url = f"{original_domain}:{port}"
                            web_targets.add(url)
            

    final_results = {}


    # Processa i risultati per creare un JSON pulito e strutturato per i target scansionati originali
    # Iteriamo sui safe_targets originali, non sui risultati Nmap basati su IP
    for domain in safe_targets:
        # Recupera l'IP del dominio
        ip_address = domain_ip_map.get(domain)
        
        # Struttura base per il dominio
        domain_result = {
            "ip": ip_address,
            "scan_type": params.get("scan_type", "fast"),
            "infrastructure": {},
            "safety_check": {},
            "scan_params_applied": target_params.get(domain, {}),  # Per-target scan parameters
            "subdomain_enum": {},
            "ports": [],
            "web_recon": {},
            "spidering": {},
            "js_analysis": {},
            "advanced_fingerprint": [],
            "content_discovery": [],
            "vhost_enum": {}
        }

        # Recupera inmap_data associato a questo IP, se esistente
        nmap_data = nmap_results.get(ip_address, {}) if ip_address else {}

        if "error" in nmap_data:
            domain_result["error"] = nmap_data["error"]
        
        # Popola info infrastruttura se disponibili (per IP o dominio)
        if ip_address and ip_address in infra_results:
             domain_result["infrastructure"] = infra_results[ip_address]
        elif domain in infra_results:
             domain_result["infrastructure"] = infra_results[domain]
             
        # Popola info safety check
        if domain in safety_results:
            domain_result["safety_check"] = safety_results[domain]
        
        # Estrazione info porte dal result aggregato sull'IP
        if "tcp" in nmap_data:
            for port, info in nmap_data["tcp"].items():
                port_info = {
                    "port": port,
                    "service": info.get("name", "unknown"),
                    "state": info.get("state", "unknown"),
                    "product": info.get("product", ""),
                    "version": info.get("version", "")
                }
                domain_result["ports"].append(port_info)
        
        final_results[domain] = domain_result

    # Aggiungi info per target skippati nel risultato finale
    for skip in skipped_targets:
        final_results[skip['target']] = {
            'skipped': True,
            'reasons': skip['reasons'],
            'warnings': skip.get('warnings', []),
            'infrastructure': infra_results.get(skip['target'], {}),
            'safety_check': safety_results.get(skip['target'], {})
        }

    # Se sono state trovate target web, lancia httpx e integra i risultati
    if web_targets:
        print(f"Target web identificati per scansione HTTPX: {len(web_targets)} target univoci riassociati ai domini.", file=sys.stderr)
        httpx_tool = HttpxTool()
        httpx_tool.run(list(web_targets), params, target_params=target_params)
        httpx_results_json = httpx_tool.get_results()
        httpx_results = safe_load_json(httpx_results_json)

        
        # Integra i risultati di httpx nella struttura del dominio corrispondente
        # ed estrai contemporaneamente la lista degli URL *vivi* da passare a Nuclei
        alive_web_targets = []
        for url, data in httpx_results.items():
            # Controlla se la richiesta httpx e' andata a buon fine (nessun mapping di 'error')
            if "error" not in data:
                 alive_web_targets.append(url)
                 
            # Estrae il dominio dall'URL in modo sicuro.
            # Se l'URL non ha schema (es. example.com:8080), urlparse necessita di // per riconoscere il netloc.
            if "://" not in url:
                parsed_url = urlparse("//" + url)
            else:
                parsed_url = urlparse(url)
                
            domain_key = parsed_url.hostname
            
            if domain_key in final_results:
                final_results[domain_key]["web_recon"][url] = data

        # === Integrazione Web Spidering (Katana) ===
        dynamic_wordlists = {} # {base_domain: [paths...]}
        
        if alive_web_targets:
            spider_tool = SpiderTool()
            spider_tool.run(alive_web_targets, params, target_params=target_params)
            spider_results = safe_load_json(spider_tool.get_results())
            
            # Raccogliamo i JS file tracciando il dominio originario che li ha scoperti
            all_js_files_with_context = []
            
            for url, findings in spider_results.items():
                domain_key = findings.get("base_domain")
                if not domain_key:
                    # Fallback fallback
                    parsed_url = urlparse("//" + url if "://" not in url else url)
                    domain_key = parsed_url.hostname
                
                if domain_key in final_results:
                     final_results[domain_key]["spidering"][url] = findings
                     
                if "error" not in findings:
                     # Aggiungiamo i path alla wordlist dinamica globale per dominio
                     if domain_key not in dynamic_wordlists:
                          dynamic_wordlists[domain_key] = set()
                          
                     if findings.get("paths_wordlist"):
                          dynamic_wordlists[domain_key].update(findings["paths_wordlist"])
                          
                     if findings.get("js_files"):
                          for js in findings["js_files"]:
                               all_js_files_with_context.append({"url": js, "origin_domain": domain_key})

        # === Integrazione Static JS Analysis (Jsluice) ===
        if all_js_files_with_context:
            # Estrai solo gli URL unici per jsluice
            unique_js_urls = list(set([x["url"] for x in all_js_files_with_context]))
            
            js_analyzer = JsAnalyzerTool()
            js_analyzer.run(unique_js_urls, params)
            js_results = safe_load_json(js_analyzer.get_results())
            
            # Il problema: Jsluice raggruppa per il dominio su cui risiede il file JS (es. cdn.company.com).
            # Noi dobbiamo mappare i path trovati nel JS al dominio ORIGINARIO che stavamo scansionando.
            
            for context in all_js_files_with_context:
                js_url = context["url"]
                origin_domain = context["origin_domain"]
                
                # Cerca i risultati di jsluice per questo specifico JS URL's base domain
                js_hosted_domain = urlparse(js_url).hostname
                if js_hosted_domain and js_hosted_domain in js_results:
                     extracted_paths = js_results[js_hosted_domain]
                     
                     if origin_domain in final_results:
                          # Manteniamo un set unico di path JS originati per questo target
                          if "endpoints" not in final_results[origin_domain]["js_analysis"]:
                               final_results[origin_domain]["js_analysis"]["endpoints"] = []
                               
                          # Usiamo set temp per non duplicare nel JSON finale
                          temp_set = set(final_results[origin_domain]["js_analysis"]["endpoints"])
                          temp_set.update(extracted_paths)
                          final_results[origin_domain]["js_analysis"]["endpoints"] = list(temp_set)
                          final_results[origin_domain]["js_analysis"]["total_extracted_endpoints"] = len(temp_set)
                          
                          if origin_domain not in dynamic_wordlists:
                               dynamic_wordlists[origin_domain] = set()
                          dynamic_wordlists[origin_domain].update(extracted_paths)

        # Convert sets back to lists for FFUF serialization
        for k in dynamic_wordlists:
             dynamic_wordlists[k] = list(dynamic_wordlists[k])

        # === Integrazione Content Discovery (Web Fuzzing Context-Aware) ===
        if alive_web_targets:
            c_discovery_tool = ContentDiscoveryTool()
            c_discovery_tool.run(alive_web_targets, params, httpx_results=httpx_results, target_params=target_params, dynamic_wordlists=dynamic_wordlists)
            c_discovery_json = c_discovery_tool.get_results()
            c_discovery_results = safe_load_json(c_discovery_json)
            
            # Integra i file e le directory trovate nel JSON
            for url, findings in c_discovery_results.items():
                if "://" not in url:
                    parsed_url = urlparse("//" + url)
                else:
                    parsed_url = urlparse(url)
                
                domain_key = parsed_url.hostname
                
                if domain_key in final_results:
                    if "error" in findings:
                        final_results[domain_key]["content_discovery"].append({"error": findings["error"]})
                    elif isinstance(findings, list) and len(findings) > 0:
                        final_results[domain_key]["content_discovery"].extend(findings)

        # === Integrazione Nuclei (Advanced Fingerprinting) ===
        if alive_web_targets:
            print(f"\nAvvio Advanced Fingerprinting con Nuclei su {len(alive_web_targets)} target web vivi...", file=sys.stderr)
            nuclei_tool = NucleiTool()
            # Nuclei elabora la lista url validati da Httpx 
            nuclei_tool.run(alive_web_targets, params, target_params=target_params)
            nuclei_results_json = nuclei_tool.get_results()
            nuclei_results = safe_load_json(nuclei_results_json)
            
            # Integra i findings di Nuclei all'interno della struttura json
            for url, findings in nuclei_results.items():
                if "://" not in url:
                    parsed_url = urlparse("//" + url)
                else:
                    parsed_url = urlparse(url)
                
                domain_key = parsed_url.hostname
                
                if domain_key in final_results:
                    if "error" in findings:
                        final_results[domain_key]["advanced_fingerprint"].append({"error": findings["error"]})
                    elif isinstance(findings, list) and len(findings) > 0:
                        # Estendi la lista vuota di array con i discovery di nuclei per questo URL
                        final_results[domain_key]["advanced_fingerprint"].extend(findings)

    else:
        print("Nessun target web (80/443) trovato per scansione HTTPX e Nuclei addizionale.", file=sys.stderr)
    
    # Creiamo un reverse mapping rapido per VhostEnumTool (domain -> base_domain)
    domain_to_base = {}
    for base, subs in grouped_domains.items():
        for sub in subs:
            domain_to_base[sub] = base
        # Assicuriamoci che anche il base punti a sé stesso
        domain_to_base[base] = base

    # Step 5: Virtual Host Enumeration
    # Fuzzing dell'header Host: per scoprire vhost nascosti sugli stessi IP
    if web_targets:
        print(f"\nAvvio VHost Enumeration su {len(web_targets)} target web...", file=sys.stderr)
        vhost_tool = VhostEnumTool(dns_resolvers=python_dns_resolvers)
        vhost_tool.run(list(web_targets), params, target_params=target_params, origin_results=origin_results, domain_to_base=domain_to_base, domain_ip_map=domain_ip_map)
        vhost_results = safe_load_json(vhost_tool.get_results())
        
        # Integra risultati nella struttura finale
        for url, vhost_data in vhost_results.items():
            # Estrae il dominio base dal target (es. "example.com:443" -> "example.com")
            base_domain = url.split(':')[0].replace('http://', '').replace('https://', '')
            if base_domain in final_results:
                final_results[base_domain]["vhost_enum"][url] = vhost_data
    else:
        print("Nessun target web per VHost Enumeration.", file=sys.stderr)
    
    # Tutti gli scan sono completati, ferma il monitoraggio IP rotation
    iprotation_monitor.stop()  # Questo ora attende la durata minima E il completamento del thread
    rotation_results_json = iprotation_monitor.get_results()
    rotation_results = safe_load_json(rotation_results_json)
    
    # Integra i risultati di IP rotation nella struttura finale
    for domain, rotation_data in rotation_results.items():
        if domain in final_results:
            final_results[domain]["ip_rotation"] = rotation_data

    # Integra i risultati della subdomain enumeration (se applicabile a questo dominio)
    # Nota: salviamo i risultati per i domini "seed" originali
    for seed, result in subdomain_results.items():
        if seed in final_results:
            final_results[seed]["subdomain_enum"] = result
    
    # Output dei risultati finali aggregati
    print(json.dumps(final_results, indent=4))

if __name__ == "__main__":
    main()
