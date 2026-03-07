import json
import subprocess
import sys
import shutil
import random
import os
import dns.resolver
import dns.exception
import re
import tldextract
import concurrent.futures
from typing import List, Dict, Any
from .base_tool import Tool

class VhostEnumTool(Tool):
    """
    Tool per la virtual host enumeration tramite fuzzing dell'header Host.
    Utilizza 'ffuf' per scoprire vhost nascosti ospitati sullo stesso IP.
    
    Tecnica: Name-based virtual hosting discovery.
    Per ogni target web, risolve il dominio a IP e fuzza l'header Host:
    con una wordlist di nomi comuni, identificando risposte che differiscono
    dalla risposta "default" del server (auto-calibration di ffuf con -ac).
    """

    SCAN_PROFILES = {
        "fast": {
            "flags": ["-ac", "-mc", "all", "-t", "40", "-timeout", "5"]
        },
        "accurate": {
            "flags": ["-ac", "-mc", "all", "-t", "80", "-timeout", "10"]
        },
        "comprehensive": {
            "flags": ["-ac", "-mc", "all", "-t", "100", "-timeout", "15"]
        },
        "stealth": {
            "flags": ["-ac", "-mc", "all", "-t", "5", "-timeout", "10", "-p", "0.5-1.5"]
        }
    }

    # Format string per gli headers di routing usati per il bypass/smuggling dei vhost.
    # {domain} verrà sostituito a runtime con la base zone (es. target.com).
    ROUTING_HEADERS_FORMATS = [
        ("Host", "FUZZ.{domain}"),
        ("X-Forwarded-Host", "FUZZ.{domain}"),
        ("X-Host", "FUZZ.{domain}"),
        ("Forwarded", "host=FUZZ.{domain}")
    ]

    def __init__(self, dns_resolvers: List[str] = None):
        """
        Inizializza il VhostEnumTool.
        Verifica la presenza di ffuf nel PATH.
        """
        super().__init__()
        self.ffuf_path = shutil.which("ffuf")
        self.dns_resolvers = dns_resolvers or ['1.1.1.1', '8.8.8.8']
        if not self.ffuf_path:
            print("ATTENZIONE: Eseguibile 'ffuf' non trovato nel PATH. Il tool fallirà se eseguito.", file=sys.stderr)

    def run(self, domains: List[str], params: Dict[str, Any], target_params: Dict[str, Dict] = None, origin_results: Dict[str, Any] = None, domain_to_base: Dict[str, str] = None, domain_ip_map: Dict[str, str] = None) -> None:
        """
        Esegue il virtual host enumeration sui target web specificati.
        
        Args:
            domains (List[str]): Lista dei target web (formato 'dominio:porta').
            params (Dict[str, Any]): Parametri della scansione (scan_type, wordlist).
            target_params (Dict[str, Dict]): Parametri specifici per ogni target (timing, max_rate).
            origin_results (Dict[str, Any]): Risultati da OriginIpTool con i mapping CDN/Origin IPs.
            domain_to_base (Dict[str, str]): Mappa un dominio/target al suo base_domain precalcolato.
            domain_ip_map (Dict[str, str]): Mappa dominio -> IP pre-risolto da HostingIntelTool.
        """
        if not self.ffuf_path:
            for target in domains:
                self.results[target] = {"error": "Eseguibile ffuf non trovato"}
            return

        if not domains:
            return

        wordlist = params.get("vhost_wordlist") or params.get("wordlist") or "wordlists/vhosts.txt"
        
        if not os.path.exists(wordlist):
            print(f"ATTENZIONE: Wordlist vhost '{wordlist}' non trovata.", file=sys.stderr)
            for target in domains:
                self.results[target] = {"error": f"Wordlist non trovata: {wordlist}"}
            return

        param_groups = self._group_by_params(domains, target_params or {})
        print(f"Grouped {len(domains)} targets into {len(param_groups)} parameter groups for vhost enum", file=sys.stderr)

        for group_key, group_domains in param_groups.items():
            timing, max_rate = group_key
            base_args = self._build_args(params, timing, max_rate)
            scan_type = params.get('scan_type', 'fast').lower()

            # Raggruppa internamente per (IPs, port, base_domain) per evitare scan duplicati
            ip_groups = {}
            
            def _resolve_target(target):
                parts = target.split(':')
                domain = parts[0]
                port = parts[1] if len(parts) > 1 else "80"
                base_domain = domain_to_base.get(domain) if domain_to_base else None
                if not base_domain:
                    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
                    if ipv4_pattern.match(domain) or ":" in domain:
                        base_domain = domain
                    else:
                        extracted = tldextract.extract(domain)
                        base_domain = extracted.registered_domain if extracted.registered_domain else domain
                
                target_ips = self._get_target_ips(domain, base_domain, origin_results, domain_ip_map)
                return target, domain, port, base_domain, tuple(sorted(target_ips))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                resolved_targets = list(executor.map(_resolve_target, group_domains))
                
            for target, domain, port, base_domain, t_ips in resolved_targets:
                if not t_ips:
                    print(f"ERRORE: Impossibile risolvere {domain} per vhost enumeration", file=sys.stderr)
                    self.results[target] = {"error": f"Impossibile risolvere il dominio {domain}"}
                    continue
                    
                ip_key = (t_ips, port, base_domain)
                if ip_key not in ip_groups:
                    ip_groups[ip_key] = []
                ip_groups[ip_key].append((target, domain))
            
            print(f"VHost scanning {len(ip_groups)} unique IP/port/base_domain combos for {len(group_domains)} targets (timing={timing}, max_rate={max_rate})", file=sys.stderr)

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                for (t_ips, port, base_domain), targets_info in ip_groups.items():
                    futures.append(
                        executor.submit(
                            self._scan_ip_group, targets_info, list(t_ips), port, base_domain, base_args, wordlist, scan_type
                        )
                    )
                # Attendiamo e logghiamo eventuali eccezioni fatali nei thread (evitando il silent-fail)
                done, _ = concurrent.futures.wait(futures)
                for f in done:
                    try:
                        f.result()
                    except Exception as e:
                        print(f"Errore critico in un thread VHost Enum: {e}", file=sys.stderr)

    def _group_by_params(self, domains: List[str], target_params: Dict[str, Dict]) -> Dict[tuple, List[str]]:
        """
        Raggruppa i target in base ai loro parametri di scansione.
        Estrae il dominio base dall'URL (es. "example.com:443" -> "example.com").
        """
        groups = {}

        for target in domains:
            # Estrae il dominio base dal target (es. "example.com:443" -> "example.com")
            base_domain = target.split(':')[0].replace('http://', '').replace('https://', '')

            params = target_params.get(base_domain, {})
            timing = params.get('timing', 'normal')
            max_rate = params.get('max_rate')

            key = (timing, max_rate)
            if key not in groups:
                groups[key] = []
            groups[key].append(target)

        return groups

    def _build_args(self, params: Dict[str, Any], timing: str, max_rate: int = None) -> List[str]:
        """
        Costruisce gli argomenti ffuf basati su scan_type, timing e max_rate.
        Restituisce la lista di argomenti base (senza target-specific args).
        """
        scan_type = params.get('scan_type', 'fast').lower()
        if scan_type not in self.SCAN_PROFILES:
            scan_type = 'fast'

        profile = self.SCAN_PROFILES[scan_type]

        # Argomenti base: output JSON, silenzioso
        cmd = [self.ffuf_path, "-json", "-s"]

        # Flag dal profilo
        cmd.extend(profile["flags"])

        # Rate limiting
        if max_rate:
            cmd.extend(["-rate", str(max_rate)])
        elif timing == 'polite':
            cmd.extend(["-rate", "10"])

        return cmd

    def _get_target_ips(self, domain: str, base_domain: str, origin_results: Dict[str, Any], domain_ip_map: Dict[str, str]) -> List[str]:
        target_ips = []
        origin_info = origin_results.get(base_domain, {}) if origin_results else {}
        
        if origin_info.get("is_behind_cdn") and origin_info.get("origin_ips"):
            target_ips = origin_info["origin_ips"]
        else:
            pre_resolved_ip = domain_ip_map.get(domain) if domain_ip_map else None
            if pre_resolved_ip:
                target_ips = [pre_resolved_ip]
            else:
                try:
                    fallback_count = min(2, len(self.dns_resolvers))
                    timeout_sec = 2.0
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = random.sample(self.dns_resolvers, fallback_count) if self.dns_resolvers else ['8.8.8.8']
                    resolver.timeout = timeout_sec
                    resolver.lifetime = timeout_sec * fallback_count
                    answers = resolver.resolve(domain, 'A')
                    target_ips = [str(answers[0])]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
                    pass
        return target_ips

    def _scan_ip_group(self, targets_info: List[tuple], target_ips: List[str], port: str, base_domain: str, base_args: List[str], wordlist: str, scan_type: str = "fast") -> None:
        """
        Esegue il vhost enumeration su un gruppo di target con stesso (IPs, porta, base_domain).
        Esegue ffuf SOLO SU UNO DEI DOMINI come 'rappresentativo' per gli header (es. X-Forwarded-Host),
        ma popola i risultati per tutti i target nel gruppo evitando richieste identiche a ffuf.
        """
        scheme = "https" if port in ("443", "8443") else "http"
        all_discovered = []
        
        representative_domain = targets_info[0][1]
        
        # Filtro Header: Ottimizzazione per scansioni fast/accurate
        if scan_type in ("fast", "accurate"):
            routing_headers = [
                ("Host", "FUZZ.{domain}".format(domain=base_domain))
            ]
        else:
            routing_headers = [
                (header_name, header_format.format(domain=base_domain))
                for header_name, header_format in self.ROUTING_HEADERS_FORMATS
            ]
        
        for target_ip in target_ips:
            # Opt: Format IPv6 address safely if present
            formatted_ip = f"[{target_ip}]" if ":" in target_ip else target_ip
            target_url = f"{scheme}://{formatted_ip}:{port}/"
            
            for header_name, header_payload in routing_headers:
                cmd = list(base_args)
                
                # Opt: Always pass a valid SNI on HTTPS proxy connections
                # Server / CDNs will drop requests to absolute IPs without an SNI matching a known config
                if scheme == "https":
                    # Usiamo il base_domain (es. target.com) invece del sottodominio specifico, 
                    # perchè il fuzzing lavora allo stesso livello (FUZZ.target.com) ed il certificato 
                    # installato è spesso un Wildcard (*.target.com). Passare un sottodominio come 
                    # SNI e chiederne un altro via Host Header triggera blocchi WAF per SNI-Mismatch.
                    cmd.extend(["-sni", base_domain])
                
                if header_name != "Host":
                    cmd.extend(["-H", f"Host: {representative_domain}"])
                
                cmd.extend([
                    "-u", target_url,
                    "-H", f"{header_name}: {header_payload}",
                    "-w", wordlist
                ])

                print(f"VHost enum su {representative_domain} (-> {target_ip}:{port}) via {header_name} (gruppo di {len(targets_info)} target)", file=sys.stderr)

                try:
                    process = subprocess.run(
                        cmd, capture_output=True, text=True, check=False, timeout=120
                    )

                    if process.returncode != 0 and not process.stdout:
                        error_msg = process.stderr.strip() if process.stderr else f"ffuf exit code: {process.returncode}"
                        print(f"Errore ffuf su {representative_domain} (IP: {target_ip} Header: {header_name}): {error_msg}", file=sys.stderr)
                        continue

                    discovered = self._parse_ffuf_output(process.stdout, base_domain)
                    for v in discovered:
                        v["target_ip_used"] = target_ip
                        v["bypassed_via"] = header_name
                    all_discovered.extend(discovered)

                    if discovered:
                        print(f"  [+] {len(discovered)} vhost trovati su {representative_domain} (IP: {target_ip}) via {header_name} per {len(targets_info)} target", file=sys.stderr)

                except subprocess.TimeoutExpired:
                    print(f"Timeout durante vhost enum su {representative_domain} (IP: {target_ip} Header: {header_name})", file=sys.stderr)
                except Exception as e:
                    print(f"Eccezione durante vhost enum su {representative_domain}: {str(e)}", file=sys.stderr)

        unique_vhosts = {}
        for v in all_discovered:
            k = v["vhost"]
            if k not in unique_vhosts:
                unique_vhosts[k] = v
                
        final_vhosts = list(unique_vhosts.values())

        # Popola risultati per tutti i target del gruppo senza dover lanciare ffuf per ognuno
        for target, domain in targets_info:
            self.results[target] = {
                "domain": domain,
                "port": port,
                "discovered_vhosts": final_vhosts,
                "count": len(final_vhosts),
                "ips_scanned": target_ips
            }

    def _parse_ffuf_output(self, stdout: str, base_domain: str) -> List[Dict[str, Any]]:
        """
        Parsa l'output JSON di ffuf ed estrae i vhost scoperti.
        
        ffuf con -json restituisce un oggetto JSON con campo "results" contenente un array di match. 
        Ogni match ha: input (FUZZ value), status, length, words, lines, url, host.
        
        Returns:
            Lista di dizionari con info sui vhost trovati.
        """
        vhosts = []

        if not stdout or not stdout.strip():
            return vhosts

        try:
            data = json.loads(stdout)
            results = data.get("results", [])

            for result in results:
                fuzz_value = result.get("input", {}).get("FUZZ", "")
                if not fuzz_value:
                    continue

                vhost_name = f"{fuzz_value}.{base_domain}"

                vhost_info = {
                    "vhost": vhost_name,
                    "status_code": result.get("status", 0),
                    "content_length": result.get("length", 0),
                    "content_words": result.get("words", 0),
                    "content_lines": result.get("lines", 0),
                    "url": result.get("url", ""),
                    "redirect_location": result.get("redirectlocation", "")
                }
                vhosts.append(vhost_info)

        except json.JSONDecodeError:
            # ffuf potrebbe restituire output non-JSON in caso di errore
            print(f"Errore parsing JSON output ffuf", file=sys.stderr)

        return vhosts

    def get_results(self) -> str:
        """
        Restituisce i risultati in formato JSON.
        """
        return json.dumps(self.results, indent=4)
