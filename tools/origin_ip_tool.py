import sys
import json
import socket
import ssl
import time
import requests
import urllib3
import concurrent.futures
import difflib
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
from .base_tool import Tool

# Disabilita messaggi di warning per certificati Insecure sulle richieste
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OriginIpTool(Tool):
    """
    Tool per identificare e validare potenziali Origin IPs (IP reali dei server)
    dietro CDN o WAF (Cloudflare, Akamai, ecc.).
    
    Analizza i domini scoperti e le informazioni infrastrutturali:
    Se il dominio principale è dietro CDN, ma alcuni sottodomini risolvono 
    su IP che NON appartengono a CDN, quegli IP vengono classificati come 
    potenziali Origin IPs.
    
    Introduce una validazione a tre livelli (SSL, Headers, Body Similarity) 
    per scartare i falsi positivi (es. IP riassegnati, vecchie macchine spente).
    """

    # Timeout molto aggressivi per scartare subito gli IP "buchi neri"
    CONNECTION_TIMEOUT = 3.0
    READ_TIMEOUT = 5.0
    
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
        Esegue la validazione a cascata (SSL -> HTTP Headers -> Similarity) 
        usando un ThreadPool per non bloccare l'esecuzione.
        """
        validated = []
        
        # 0. Fase di Calibrazione: Raccogliamo le firme (signature) dal dominio ufficiale (che passa per la CDN)
        baseline_data = self._fetch_baseline(base_domain)
        if not baseline_data:
             print(f"      [!] Impossibile estrarre baseline dal target {base_domain}. Check SSL sarà l'unico stringente.", file=sys.stderr)
             
        def check_candidate(ip):
            # Priorità 1: Validazione Certificato SSL (Fast-Pass)
            if self._validate_ssl(ip, base_domain):
                return ip, "ssl_match"
                
            # Se la baseline non c'è ed il cert ha fallito, non possiamo procedere oltre
            if not baseline_data:
                 return None, None
                 
            # Priorità 2 & 3: Validazione Applicativa (Headers & Body via richieste interattive)
            if self._validate_http(ip, base_domain, baseline_data):
                return ip, "http_match"
                
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
             future_to_ip = {executor.submit(check_candidate, ip): ip for ip in candidates}
             for future in concurrent.futures.as_completed(future_to_ip):
                 ip = future_to_ip[future]
                 try:
                     result_ip, match_type = future.result()
                     if result_ip:
                         validated.append(result_ip)
                 except Exception as exc:
                     # Silently ignore general thread exceptions to keep ASM running
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
            
            with socket.create_connection((ip, 443), timeout=self.CONNECTION_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=base_domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                         return False
                    
                    # Cerca nei Subject Alternative Names (SAN)
                    if 'subjectAltName' in cert:
                        for key, value in cert['subjectAltName']:
                            if key == 'DNS' and (value == base_domain or value == f"*.{base_domain}"):
                                return True
                                
                    # Cerca nel Common Name (CN) se non trovato nei SAN
                    if 'subject' in cert:
                        for entry in cert['subject']:
                            for key, value in entry:
                                if key == 'commonName' and (value == base_domain or value == f"*.{base_domain}"):
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
            resp = requests.get(target_url, headers=self.DEFAULT_HEADERS, timeout=self.READ_TIMEOUT, verify=False, allow_redirects=True)
            baseline['headers'] = dict(resp.headers)
            baseline['body_length'] = len(resp.text)
            baseline['body'] = resp.text
            baseline['title'] = self._extract_title(resp.text)
            
            return baseline
        except Exception:
            # Fallback a HTTP
            try:
                target_url = f"http://{base_domain}"
                resp = requests.get(target_url, headers=self.DEFAULT_HEADERS, timeout=self.READ_TIMEOUT, verify=False, allow_redirects=True)
                baseline['headers'] = dict(resp.headers)
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
        signature_keys = ['Server', 'X-Powered-By', 'Set-Cookie']
        custom_signatures = {k: v for k, v in baseline_headers.items() if k in signature_keys or k.startswith('X-')}

        for url in test_urls:
            for header_name, header_payload in self.ROUTING_HEADERS:
                
                req_headers = dict(self.DEFAULT_HEADERS)
                req_headers[header_name] = header_payload.format(domain=base_domain)
                
                # SNI injection finta sulla request obj se in HTTPS
                if url.startswith("https://"):
                    req_headers["Host"] = base_domain # requests userà internamente l'host per l'SNI (anche bypassando l'IP) nella nuova versione di urllib3 se opportunamente tunata, ma noi l'abbiamo già controllato tramite _validate_ssl
                
                try:
                    resp = requests.get(url, headers=req_headers, timeout=self.READ_TIMEOUT, verify=False, allow_redirects=False)
                    resp_headers = dict(resp.headers)
                    resp_body = resp.text
                    resp_title = self._extract_title(resp_body)
                    
                    # 1. Similarity Check su Headers Espliciti (Server signature)
                    matched_signatures = 0
                    for sig_key, sig_val in custom_signatures.items():
                        if sig_key in resp_headers:
                            # Controlliamo substring nei cookie o match esatti in altri header
                            if sig_key == 'Set-Cookie':
                                # Estrarre il key name del cookie (es. PHPSESSID)
                                base_cookie_keys = [c.split('=')[0] for c in sig_val.split(';')]
                                resp_cookie_keys = [c.split('=')[0] for c in resp_headers[sig_key].split(';')]
                                if any(bk in resp_cookie_keys for bk in base_cookie_keys):
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
                        if len_ratio > 0.85: 
                            # Se la lunghezza differisce di max 15%, calcoliamo la vera similarità bloccante (ratio() = >0.85 approx match)
                            # Questo step è pesante per body string > 1 MB, ma la limitiamo testando l'header length
                            similarity = difflib.SequenceMatcher(None, baseline_body[:50000], resp_body[:50000]).ratio()
                            if similarity > 0.85:
                                return True
                                
                except requests.exceptions.Timeout:
                    # Se in timeout, è inutile provare gli altri header di routing, la macchina è giù o scarta l'IP
                    break 
                except requests.exceptions.RequestException:
                    pass
                    
        return False
        
    def _extract_title(self, html_content: str) -> str:
        """Estrae velocemente il <title> da un documento HTML senza parse pesanti"""
        if not html_content:
            return ""
        start = html_content.find("<title>")
        if start == -1:
            start = html_content.find("<TITLE>")
        if start != -1:
            start += 7
            end = html_content.find("</title>", start)
            if end == -1:
                end = html_content.find("</TITLE>", start)
            if end != -1:
                return html_content[start:end].strip()
        return ""

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
