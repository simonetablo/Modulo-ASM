import os
import sys
import time
import random
import string
import requests
import concurrent.futures
import dns.resolver
import dns.exception
from typing import List, Dict, Any
from .base_tool import Tool

class DnsManagerTool(Tool):
    """
    Tool per la gestione centralizzata dei DNS resolvers pubblici.
    Parametri caricati da config/dns_manager/config.json.
    """

    # Defaults hardcoded come ultimo fallback se nessun file config è presente
    DEFAULT_CONFIG = {
        "max_resolvers": 50,
        "freshness_hours": 24,
        "doh_max_retries": 3,
        "validation_max_workers": 50
    }

    RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    TRUSTED_RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"
    LOCAL_RESOLVERS_FILE = "wordlists/resolvers.txt"
    LOCAL_TRUSTED_RESOLVERS_FILE = "wordlists/resolvers-trusted.txt"
    HARDCODED_FALLBACK = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9']
    
    DOH_ENDPOINTS = [
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
        "https://doh.quad9.net/dns-query"
    ]
    
    MAX_TRUSTED_FAILURES = 10

    def __init__(self):
        super().__init__()
        self.resolvers = []
        os.makedirs("wordlists", exist_ok=True)
        # Carica configurazione
        file_config = self.load_config("dns_manager")
        self._config = {**self.DEFAULT_CONFIG, **file_config}

    def run(self, domains: List[str] = None, params: Dict[str, Any] = None) -> None:
        pass # Metodo inutilizzato in questo contesto, presente per conformità alla classe Tool

    def get_trusted_resolvers(self) -> List[str]:
        if not self._is_local_file_fresh(self.LOCAL_TRUSTED_RESOLVERS_FILE):
            self._download_trusted_resolvers()
        
        resolvers = self._load_local_resolvers(self.LOCAL_TRUSTED_RESOLVERS_FILE)
        return resolvers if resolvers else self.HARDCODED_FALLBACK

    def get_resolvers(self, max_count: int = None) -> List[str]:
        """
        Restituisce una lista di DNS Resolvers.
        max_count: se None, usa il valore dal config; se 0, restituisce tutti.
        """
        if not self._is_local_file_fresh(self.LOCAL_RESOLVERS_FILE):
            self._download_resolvers()

        resolvers = self._load_local_resolvers(self.LOCAL_RESOLVERS_FILE)
        trusted = self.get_trusted_resolvers()
        
        if not resolvers:
            print("  [!] Nessun resolver trovato nel file, utilizzo fallback.", file=sys.stderr)
            resolvers = trusted

        # Ritorna i primi N resolver per non sovraccaricare il resolver python locale, 
        # oppure tutti se richiesto (passando 0 o None), ideale per massdns/puredns che gestiscono bene liste immense.
        if max_count is None:
            max_count = self._config.get("max_resolvers", 50)
        if max_count and max_count > 0:
            resolvers = resolvers[:max_count]
            
        # Assicurati di ritornare sempre almeno un resolver fidato in coda come fallback
        trusted_fallback = random.choice(trusted)
        if trusted_fallback not in resolvers:
            resolvers.append(trusted_fallback)
            
        return resolvers

    def _is_local_file_fresh(self, filepath: str) -> bool:
        if not os.path.exists(filepath):
            return False
            
        file_mod_time = os.path.getmtime(filepath)
        current_time = time.time()
        age_hours = (current_time - file_mod_time) / 3600
        
        return age_hours < self._config.get("freshness_hours", 24)

    def _download_list(self, url: str, dest_file: str, do_sanity_check: bool = False) -> None:
        print(f"  [*] Download da {url}...", file=sys.stderr)
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            response.raise_for_status()
            content = response.text
                
            # Filtra linee vuote o commenti
            valid_ips = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
            
            if valid_ips:
                if do_sanity_check:
                    print(f"  [*] Scaricati {len(valid_ips)} resolvers. Avvio sanity check...", file=sys.stderr)
                    valid_ips = self._filter_valid_resolvers(valid_ips)
                
                if valid_ips:
                    with open(dest_file, 'w') as f:
                        f.write('\n'.join(valid_ips))
                    print(f"  [+] Salvati {len(valid_ips)} resolvers in {dest_file}", file=sys.stderr)
                else:
                    print(f"  [!] Nessun resolver ha superato il sanity check per {dest_file}.", file=sys.stderr)
            else:
                print(f"  [!] Nessun resolver valido scaricato da {url}.", file=sys.stderr)
                
        except Exception as e:
            print(f"  [!] Errore durante il download dal URL {url}: {e}", file=sys.stderr)

    def _download_resolvers(self) -> None:
        self._download_list(self.RESOLVERS_URL, self.LOCAL_RESOLVERS_FILE, do_sanity_check=True)

    def _download_trusted_resolvers(self) -> None:
        self._download_list(self.TRUSTED_RESOLVERS_URL, self.LOCAL_TRUSTED_RESOLVERS_FILE, do_sanity_check=False)

    def _load_local_resolvers(self, filepath: str) -> List[str]:
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            return []

    def get_results(self) -> str:
        return '{"status": "ok"}'

    def _filter_valid_resolvers(self, resolvers: List[str], max_workers: int = None) -> List[str]:
        """
        Esegue un sanity check sui resolver per scartare quelli misconfigurati o "poisoned".
        Verifica che risolvano un dominio noto ed eludano un dominio inesistente (NXDOMAIN).
        """
        valid_resolvers = []
        random_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        nxdomain_target = f"{random_prefix}.com"
        known_target = "example.com"
        
        def check_resolver(ip: str) -> str:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ip]
            resolver.timeout = 2
            resolver.lifetime = 2
            
            try:
                # 1. Deve restituire NXDOMAIN per un dominio inesistente
                try:
                    resolver.resolve(nxdomain_target, 'A')
                    return None # Ha risolto, è poisoned
                except dns.resolver.NXDOMAIN:
                    pass # Corretto
                except Exception:
                    return None # Timeout, SERVFAIL ecc.
                    
                # 2. Deve risolvere un dominio esistente
                resolver.resolve(known_target, 'A')
                return ip
                
            except Exception:
                return None
                
        if max_workers is None:
            max_workers = self._config.get("validation_max_workers", 50)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Per evitare lunghissimi tempi, testiamone un subset se sono troppi.
            # Trickest resolver list è di circa ~10.000 IP.
            # Facciamo il control su massimo 500 IPs.
            results = executor.map(check_resolver, resolvers[:500])
            
        for ip in results:
            if ip:
                valid_resolvers.append(ip)
                
        return valid_resolvers

    def _resolve_doh(self, domain: str, proxy_list: List[str] = None) -> bool:
        """
        Risolve via HTTPS (DoH) un singolo dominio.
        Effettua un massimo di 3 retry in caso di errore di connettività proxy.
        Ritorna True se il dominio esiste (valido), False altrimenti.
        """
        max_retries = self._config.get("doh_max_retries", 3)
        
        for attempt in range(max_retries):
            # Ad ogni iterazione scegliamo randomicamente Endpoint e Proxy (Rotazione IP)
            endpoint = random.choice(self.DOH_ENDPOINTS)
            proxies = None
            
            if proxy_list:
                selected_proxy = random.choice(proxy_list)
                proxies = {
                    "http": selected_proxy,
                    "https": selected_proxy
                }
                
            url = f"{endpoint}?name={domain}&type=A"
            headers = {'Accept': 'application/dns-json'}
            
            try:
                # Esecuzione proxyata del DoH
                response = requests.get(url, headers=headers, proxies=proxies, timeout=5)
                
                # Se l'API DoH o il WAF bloccano la richiesta es: 403 Forbidden,
                # skippiamo questo endpoint riprovando.
                if response.status_code != 200:
                    continue
                    
                data = response.json()
                
                # 'Status' segue lo standard DNS: 0 = NOERROR, 3 = NXDOMAIN, ecc.
                status = data.get("Status")
                
                if status == 0:
                    # Non basta lo status 0 (potrebbe esser un CNAME o vuoto),
                    # verifichiamo ci sia ALMENO un IP di ritorno nel block 'Answer'.
                    return "Answer" in data
                elif status == 3:
                    return False # NXDOMAIN certo
                else:
                    return False
                    
            except Exception:
                # Timeout, ConnectionError (spesso colpa di proxy morti), proseguiamo col retry
                continue
                
        # Se tutti i tentativi esauriscono i retry e vanno in timeout,
        # per sicurezza teniamo il dominio per non scartare roba viva a causa
        # di proxy lenti
        print(f"  [!] DoH fallback fail for {domain}: exceeded retries.", file=sys.stderr)
        return True

    def double_check(self, domains: List[str], use_doh: bool = False, proxy_list: List[str] = None) -> List[str]:
        """
        Valida una lista di domini utilizzando SOLO i resolver fidati.
        Supporta modalità Standard (UDP) o modalità Proxy Rotante (DNS-over-HTTPS).
        """
        if not domains:
            return []
            
        print(f"Double check su {len(domains)} domini con DNS fidati (DoH Proxy mode: {use_doh})...", file=sys.stderr)
        
        if use_doh:
            valid_domains = []
            
            # Modalità DoH (Multithreaded per coprire l'overhead TCP/HTTP e proxy)
            # Parallelizziamo le requests HTTP.
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                # Esegue la chiamata mantenendo il riferimento dominio->future
                future_to_domain = {executor.submit(self._resolve_doh, dom, proxy_list): dom for dom in domains}
                
                for future in concurrent.futures.as_completed(future_to_domain):
                    dom = future_to_domain[future]
                    is_valid = future.result()
                    if is_valid:
                        valid_domains.append(dom)
                        
            return valid_domains
        else:
            # Modalità classica UDP
            valid_domains = []
            consecutive_errors = 0
            
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = self.get_trusted_resolvers()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            for domain in domains:
                if consecutive_errors >= self.MAX_TRUSTED_FAILURES:
                    print(f"  [!] Raggiunto max errori consecutivi ({self.MAX_TRUSTED_FAILURES}) sui DNS fidati in modalita UDP. Interrompo double_check per evitare ban e ritorno i domini originali rimanenti non validati come precaution.", file=sys.stderr)
                    # Fallback
                    valid_domains.extend(domains[domains.index(domain):])
                    break
                    
                try:
                    resolver.resolve(domain, 'A')
                    valid_domains.append(domain)
                    consecutive_errors = 0 
                except dns.resolver.NXDOMAIN:
                    consecutive_errors = 0 
                except dns.exception.Timeout:
                    consecutive_errors += 1
                except Exception as e:
                    consecutive_errors += 1
                    
            return valid_domains
