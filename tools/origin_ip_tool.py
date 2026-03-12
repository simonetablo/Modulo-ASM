import sys
import json
import socket
import ssl
import time
import requests
import urllib3
import concurrent.futures
import difflib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
from .base_tool import Tool

# Disabilita messaggi di warning per certificati Insecure sulle richieste
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OriginIpTool(Tool):
    """
    Tool per identificare e validare potenziali Origin IPs (IP reali dei server)
    dietro CDN o WAF (Cloudflare, Akamai, ecc.).
    Parametri caricati da config/origin_ip/config.json.
    """

    # Defaults hardcoded come ultimo fallback se nessun file config è presente
    DEFAULT_CONFIG = {
        "connection_timeout": 3.0,
        "read_timeout": 5.0,
        "similarity_threshold": 0.85,
        "length_ratio_threshold": 0.85,
        "max_body_compare_length": 50000,
        "max_workers": 10
    }


    
    # Header di default per bypassare blocchi WAF base
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }

    # Routine di header da testare se il proxy backend maschera l'host diretto
    ROUTING_HEADERS = [
        ("Host", "{domain}"),
        ("X-Forwarded-Host", "{domain}"),
        ("X-Host", "{domain}"),
        ("Forwarded", "host={domain}")
    ]

    def __init__(self, dns_resolvers: List[str] = None):
        super().__init__()
        self.results = {}
        self.dns_resolvers = dns_resolvers or ['1.1.1.1', '8.8.8.8']
        # Carica configurazione
        file_config = self.load_config("origin_ip")
        self._config = {**self.DEFAULT_CONFIG, **file_config}

    def run(self, domains: List[str], params: Dict[str, Any], infra_results: Dict[str, Any] = None, grouped_domains: Dict[str, List[str]] = None) -> None:
        """
        Analizza i domini e l'infrastruttura per trovare e validare gli Origin IPs.
        """
        if not infra_results or "_ip_map" not in infra_results:
            print("OriginIpTool: Nessun mapping dominio-IP fornito (manca _ip_map).", file=sys.stderr)
            return
            
        if not grouped_domains:
            print("OriginIpTool: Nessun raggruppamento domini fornito.", file=sys.stderr)
            return

        domain_ip_map = infra_results.get("_ip_map", {})
        domains_count = sum(len(subs) for subs in grouped_domains.values())

        print(f"Avvio ricerca e validazione Origin IPs su {domains_count} target...", file=sys.stderr)

        for base_domain, subdomains in grouped_domains.items():
            self.results[base_domain] = {"origin_ips": [], "cdn_ips": [], "is_behind_cdn": False}
            
            origin_candidates = set()
            cdn_ips = set()
            
            # 1. Identificazione CDN
            base_infra = infra_results.get(base_domain, {})
            is_base_cdn = self._is_cdn(base_infra)
            if is_base_cdn:
                self.results[base_domain]["is_behind_cdn"] = True
                
            # 2. Estrazione Candidati
            for sub in subdomains:
                sub_infra = infra_results.get(sub, {})
                ip = domain_ip_map.get(sub)
                
                if not ip:
                    continue
                    
                ip_infra = infra_results.get(ip, sub_infra)
                
                if self._is_cdn(ip_infra):
                    cdn_ips.add(ip)
                else:
                    origin_candidates.add(ip)
                    
            self.results[base_domain]["cdn_ips"] = list(cdn_ips)
            
            # Se è dietro CDN e abbiamo candidati, procediamo con la VERA validazione attiva
            if self.results[base_domain]["is_behind_cdn"] and origin_candidates:
                print(f"  [!] {base_domain} usa CDN. Validazione in corso di {len(origin_candidates)} candidati Origin IPs...", file=sys.stderr)
                
                validated_ips = self._validate_origin_ips(base_domain, list(origin_candidates))
                
                self.results[base_domain]["origin_ips"] = validated_ips
                
                if validated_ips:
                    print(f"  [+] Validazione completata: confermati {len(validated_ips)} Origin IPs per {base_domain} ({validated_ips[:2]}...).", file=sys.stderr)
                else:
                    print(f"  [-] Nessun candidato Origin IP ha superato la validazione per {base_domain}.", file=sys.stderr)
            else:
                # Se non c'è CDN, gli IP ritornati dal DNS sono già gli origin di fatto
                self.results[base_domain]["origin_ips"] = list(origin_candidates)

    def _is_cdn(self, infra_data: Dict[str, Any]) -> bool:
        """Controlla se i dati indicano presenza di CDN/WAF/Cloud Router"""
        if not infra_data:
             return False
        return infra_data.get("has_infrastructure", False)

    def _validate_origin_ips(self, base_domain: str, candidates: List[str]) -> List[str]:
        """
        Esegue la validazione a cascata (Fase Fast Probe -> SSL -> HTTP Headers -> Similarity) 
        usando HttpxTool per la velocità iniziale e ThreadPool per la profondità.
        """
        from .httpx_tool import HttpxTool
        validated = []
        
        # 1. Fase di Fast Probe: Eliminiamo subito gli IP che non rispondono a nulla (Porta 80/443)
        # Migliorato: Iniettiamo l'header Host (e SNI) per evitare drop silenti da parte di LB/WAF.
        print(f"      [*] Probing intelligente di {len(candidates)} candidati via Httpx (Host: {base_domain})...", file=sys.stderr)
        probe_urls = []
        for ip in candidates:
            probe_urls.append(f"https://{ip}/")
            probe_urls.append(f"http://{ip}/")
            
        validator = HttpxTool()
        # Header di base per il probe: proviamo con Host ed eventualmente gli altri se la lista è piccola
        # Per speed, usiamo l'Host principale.
        probe_headers = {"Host": base_domain}
        
        # Eseguiamo il probe. Nota: httpx userà l'IP come target ma invierà l'header Host corretto.
        alive_probe_urls = set(validator.verify_urls(probe_urls, headers=probe_headers))
        
        # Estraiamo gli IP che hanno almeno un URL vivo
        alive_ips = set()
        for url in alive_probe_urls:
            p = urlparse(url)
            # Se httpx ha seguito redirect a domini esterni, lo ignoriamo e prendiamo l'hostname originale (IP)
            hostname = p.hostname
            # Se hostname sembra un IP, lo aggiungiamo
            if hostname and (hostname.replace('.', '').isdigit() or ':' in hostname):
                alive_ips.add(hostname)
            
        if not alive_ips:
            # Se fallisce con Host header, facciamo un ultimissimo tentativo veloce con X-Forwarded-Host 
            # (Raro che serva nel probe ma utile se il LB droppa Host diretti)
            print(f"      [*] Host header fallito, tentativo fallback con routing headers...", file=sys.stderr)
            probe_headers_alt = {"X-Forwarded-Host": base_domain}
            alive_probe_urls_alt = set(validator.verify_urls(probe_urls, headers=probe_headers_alt))
            for url in alive_probe_urls_alt:
                p = urlparse(url)
                hostname = p.hostname
                if hostname and (hostname.replace('.', '').isdigit() or ':' in hostname):
                    alive_ips.add(hostname)
            
        if not alive_ips:
            return []
            
        print(f"      [*] {len(alive_ips)} IP rispondono al probe. Avvio validazione SSL/Similarity...", file=sys.stderr)

        # 2. Fase di Calibrazione Baseline
        baseline_data = self._fetch_baseline(base_domain)
        if not baseline_data:
             print(f"      [!] Impossibile estrarre baseline dal target {base_domain}. Check SSL sarà l'unico stringente.", file=sys.stderr)
             
        def check_candidate(ip):
            # Priorità 1: Validazione Certificato SSL (Fast-Pass)
            if self._validate_ssl(ip, base_domain):
                return ip, "ssl_match"
                
            # Se la baseline non c'è ed il cert ha fallito, non procediamo oltre
            if not baseline_data:
                 return None, None
                 
            # Priorità 2 & 3: Validazione Applicativa (Headers & Body via richieste interattive)
            if self._validate_http(ip, base_domain, baseline_data):
                return ip, "http_match"
                
            return None, None

        # Eseguiamo solo su alive_ips
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(alive_ips), self._config.get("max_workers", 10))) as executor:
             future_to_ip = {executor.submit(check_candidate, ip): ip for ip in alive_ips}
             for future in concurrent.futures.as_completed(future_to_ip):
                 ip = future_to_ip[future]
                 try:
                     result_ip, match_type = future.result()
                     if result_ip:
                         validated.append(result_ip)
                 except Exception:
                     pass

        return validated

    def _validate_ssl(self, ip: str, base_domain: str) -> bool:
        """
        Tenta una connessione sulla porta 443 specificando il ServerName (SNI).
        Estrae il certificato e verifica che il dominio atteso sia nei SAN o nel CN.
        """
        try:

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Ignoriamo chain issues (es. Let's Encrypt scaduti) 
            
            with socket.create_connection((ip, 443), timeout=self._config.get("connection_timeout", 3.0)) as sock:
                with context.wrap_socket(sock, server_hostname=base_domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                         return False
                    
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Cerca nei Subject Alternative Names (SAN)
                    try:
                        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = ext.value.get_values_for_type(x509.DNSName)
                        for value in sans:
                            if value == base_domain or value == f"*.{base_domain}":
                                return True
                    except x509.ExtensionNotFound:
                        pass
                                
                    # Cerca nel Common Name (CN) se non trovato nei SAN
                    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                        value = attr.value
                        if isinstance(value, str) and (value == base_domain or value == f"*.{base_domain}"):
                            return True
        except Exception:
             pass
        return False
        
    def _fetch_baseline(self, base_domain: str) -> Dict[str, Any]:
        """
        Raccoglie le Header Signature ed il Body dal dominio pubblico per fare la comparazione in seguito.
        """
        baseline = {}
        target_url = f"https://{base_domain}"
        
        try:
            resp = requests.get(target_url, headers=self.DEFAULT_HEADERS, timeout=self._config.get("read_timeout", 5.0), verify=False, allow_redirects=True)
            baseline['headers'] = {k.lower(): v for k, v in resp.headers.items()}
            baseline['cookies'] = list(resp.cookies.keys())
            baseline['body_length'] = len(resp.text)
            baseline['body'] = resp.text
            baseline['title'] = self._extract_title(resp.text)
            
            return baseline
        except Exception:
            # Fallback a HTTP
            try:
                target_url = f"http://{base_domain}"
                resp = requests.get(target_url, headers=self.DEFAULT_HEADERS, timeout=self._config.get("read_timeout", 5.0), verify=False, allow_redirects=True)
                baseline['headers'] = {k.lower(): v for k, v in resp.headers.items()}
                baseline['cookies'] = list(resp.cookies.keys())
                baseline['body_length'] = len(resp.text)
                baseline['body'] = resp.text
                baseline['title'] = self._extract_title(resp.text)
                
                return baseline
            except Exception:
                return {}

    def _validate_http(self, ip: str, base_domain: str, baseline: Dict[str, Any]) -> bool:
        """
        Invia HTTP Request all'IP candidato iterando gli header di routing (Host, X-Forwarded-Host ecc).
        Restituisce True se trova similarità di Headers o Content-body rispetto alla baseline.
        """
        test_urls = [f"https://{ip}/", f"http://{ip}/"]
        
        baseline_headers = baseline.get('headers', {})
        baseline_body = baseline.get('body', '')
        baseline_title = baseline.get('title', '')
        
        # Header "sensibili" che indicano forte somiglianza se matchano esplicitamente
        signature_keys = ['server', 'x-powered-by', 'set-cookie']
        custom_signatures = {k: v for k, v in baseline_headers.items() if k in signature_keys or k.startswith('x-')}

        for url in test_urls:
            for header_name, header_payload in self.ROUTING_HEADERS:
                
                req_headers = dict(self.DEFAULT_HEADERS)
                req_headers[header_name] = header_payload.format(domain=base_domain)
                
                # SNI injection finta sulla request obj se in HTTPS
                if url.startswith("https://"):
                    req_headers["Host"] = base_domain # requests userà internamente l'host per l'SNI (anche bypassando l'IP) nella nuova versione di urllib3 se opportunamente tunata, ma noi l'abbiamo già controllato tramite _validate_ssl
                
                try:
                    resp = requests.get(url, headers=req_headers, timeout=self._config.get("read_timeout", 5.0), verify=False, allow_redirects=False)
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    resp_body = resp.text
                    resp_title = self._extract_title(resp_body)
                    
                    # 1. Similarity Check su Headers Espliciti (Server signature)
                    matched_signatures = 0
                    for sig_key, sig_val in custom_signatures.items():
                        if sig_key in resp_headers:
                            # Controlliamo substring nei cookie o match esatti in altri header
                            if sig_key == 'set-cookie':
                                # Estrarre i cookie name tracciati in precedenza e compararli
                                base_cookie_keys = baseline.get('cookies', [])
                                resp_cookie_keys = list(resp.cookies.keys())
                                if any(bk in resp_cookie_keys for bk in base_cookie_keys if bk):
                                    matched_signatures += 1
                            elif resp_headers[sig_key] == sig_val:
                                matched_signatures += 1
                                
                    if matched_signatures > 0 and len(custom_signatures) > 0:
                        # Abbiamo identificato univocamente l'app layer
                        return True
                        
                    # 2. Similarity Check su Title
                    if baseline_title and resp_title and baseline_title == resp_title:
                        # Match 1:1 del titolo del sito
                        return True
                        
                    # 3. Similarity Check Elastico su HTML Body (se Title assente o dinamico)
                    if baseline_body and resp_body:
                        # Ratio semplice sulle lunghezze prima di fare un diff pesante
                        len_ratio = min(len(baseline_body), len(resp_body)) / max(len(baseline_body), len(resp_body))
                        if len_ratio > self._config.get("length_ratio_threshold", 0.85): 
                            # Se la lunghezza differisce di max 15%, calcoliamo la vera similarità bloccante (ratio() = >0.85 approx match)
                            # Questo step è pesante per body string > 1 MB, ma la limitiamo testando l'header length
                            similarity = difflib.SequenceMatcher(None, baseline_body[:self._config.get("max_body_compare_length", 50000)], resp_body[:self._config.get("max_body_compare_length", 50000)]).ratio()
                            if similarity > self._config.get("similarity_threshold", 0.85):
                                return True
                                
                except requests.exceptions.Timeout:
                    # Se in timeout, è inutile provare gli altri header di routing, la macchina è giù o scarta l'IP
                    break 
                except requests.exceptions.RequestException:
                    pass
                    
        return False
        
    def _extract_title(self, html_content: str) -> str:
        """Estrae velocemente il <title> da un documento HTML senza parse pesanti (case-insensitive)"""
        if not html_content:
            return ""
        lower = html_content.lower()
        start = lower.find("<title>")
        if start != -1:
            start += 7
            end = lower.find("</title>", start)
            if end != -1:
                return html_content[start:end].strip()
        return ""

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
