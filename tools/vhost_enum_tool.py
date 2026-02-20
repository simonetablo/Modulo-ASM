import json
import subprocess
import sys
import shutil
import random
import dns.resolver
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
            "threads": 40,
            "flags": ["-ac", "-mc", "all", "-t", "40", "-timeout", "5"]
        },
        "accurate": {
            "threads": 80,
            "flags": ["-ac", "-mc", "all", "-t", "80", "-timeout", "10"]
        },
        "stealth": {
            "threads": 5,
            "flags": ["-ac", "-mc", "all", "-t", "5", "-timeout", "10", "-p", "0.5-1.5"]
        },
        "noisy": {
            "threads": 150,
            "flags": ["-ac", "-mc", "all", "-t", "150", "-timeout", "5"]
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

    def run(self, domains: List[str], params: Dict[str, Any], target_params: Dict[str, Dict] = None, origin_results: Dict[str, Any] = None, domain_to_base: Dict[str, str] = None) -> None:
        """
        Esegue il virtual host enumeration sui target web specificati.
        
        Args:
            domains (List[str]): Lista dei target web (formato 'dominio:porta').
            params (Dict[str, Any]): Parametri della scansione (scan_type, wordlist).
            target_params (Dict[str, Dict]): Parametri specifici per ogni target (timing, max_rate).
            origin_results (Dict[str, Any]): Risultati da OriginIpTool con i mapping CDN/Origin IPs.
            domain_to_base (Dict[str, str]): Mappa un dominio/target al suo base_domain precalcolato.
        """
        if not self.ffuf_path:
            for target in domains:
                self.results[target] = {"error": "Eseguibile ffuf non trovato"}
            return

        if not domains:
            return

        # Determina la wordlist da usare
        wordlist = params.get("vhost_wordlist") or params.get("wordlist") or "wordlists/vhosts.txt"

        # Raggruppa i target in base ai loro parametri di scansione
        param_groups = self._group_by_params(domains, target_params or {})

        print(f"Grouped {len(domains)} targets into {len(param_groups)} parameter groups for vhost enum", file=sys.stderr)

        # Scansiona ogni gruppo di parametri
        for group_key, group_domains in param_groups.items():
            timing, max_rate = group_key

            # Costruisce gli argomenti ffuf per questo gruppo
            base_args = self._build_args(params, timing, max_rate)

            print(f"VHost scanning {len(group_domains)} targets (timing={timing}, max_rate={max_rate})", file=sys.stderr)

            # Scansiona ogni target nel gruppo
            for target in group_domains:
                self._scan_target(target, base_args, wordlist, origin_results, domain_to_base)

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

    def _scan_target(self, target: str, base_args: List[str], wordlist: str, origin_results: Dict[str, Any] = None, domain_to_base: Dict[str, str] = None) -> None:
        """
        Esegue il vhost enumeration su un singolo target.
        
        Risolve il dominio a IP e configura ffuf per fuzzare l'header Host:
        inviando richieste all'IP con header Host: FUZZ.<dominio_base>

        Args:
            target: Target nel formato 'dominio:porta'
            base_args: Argomenti ffuf base costruiti da _build_args
            wordlist: Percorso alla wordlist per il fuzzing
            origin_results: Dizionario con risultati OriginIpTool
            domain_to_base: Mapping target -> base_domain
        """
        # Parsing del target: dominio:porta
        parts = target.split(':')
        domain = parts[0]
        port = parts[1] if len(parts) > 1 else "80"

        # Recupera base_domain dalla mappa passata, o fai fallback se non trovato
        base_domain = domain_to_base.get(domain) if domain_to_base else None
        if not base_domain:
            parts_d = domain.split('.')
            base_domain = f"{parts_d[-2]}.{parts_d[-1]}" if len(parts_d) >= 2 else domain

        target_ips = []
        origin_info = origin_results.get(base_domain, {}) if origin_results else {}
        
        if origin_info.get("is_behind_cdn") and origin_info.get("origin_ips"):
            target_ips = origin_info["origin_ips"]
            print(f"[*] {domain} è dietro CDN. VHost Enum su {len(target_ips)} Origin IPs ({target_ips})", file=sys.stderr)
        else:
            try:
                # Fallback mode using fast/noisy scanning profile for dynamic resolver selection
                fallback_count = min(2, len(self.dns_resolvers))
                timeout_sec = 2.0
                
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = random.sample(self.dns_resolvers, fallback_count) if self.dns_resolvers else ['8.8.8.8']
                resolver.timeout = timeout_sec
                resolver.lifetime = timeout_sec * fallback_count
                
                answers = resolver.resolve(domain, 'A')
                target_ips = [str(answers[0])]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException) as e:
                print(f"ERRORE: Impossibile risolvere {domain} per vhost enumeration -> {e}", file=sys.stderr)
                self.results[target] = {"error": f"Impossibile risolvere il dominio {domain}"}
                return

        scheme = "https" if port in ("443", "8443") else "http"
        all_discovered = []
        
        # Generiamo i routing headers finali per questo specifico target
        routing_headers = [
            (header_name, header_format.format(domain=domain))
            for header_name, header_format in self.ROUTING_HEADERS_FORMATS
        ]
        
        for target_ip in target_ips:
            target_url = f"{scheme}://{target_ip}:{port}/"
            
            for header_name, header_payload in routing_headers:
                cmd = list(base_args)
                
                # Se non stiamo fuzzando l'Host standard, dobbiamo comunque inviare un Host valido 
                # per evitare che il webserver (o la CDN/WAF) scarti a priori la richiesta malformata.
                if header_name != "Host":
                    cmd.extend(["-H", f"Host: {domain}"])
                
                cmd.extend([
                    "-u", target_url,
                    "-H", f"{header_name}: {header_payload}",
                    "-w", wordlist
                ])

                print(f"VHost enum su {domain} (-> {target_ip}:{port}) via {header_name}", file=sys.stderr)

                try:
                    process = subprocess.run(
                        cmd, capture_output=True, text=True, check=False, timeout=120
                    )

                    if process.returncode != 0 and not process.stdout:
                        error_msg = process.stderr.strip() if process.stderr else f"ffuf exit code: {process.returncode}"
                        print(f"Errore ffuf su {target} (IP: {target_ip} Header: {header_name}): {error_msg}", file=sys.stderr)
                        continue

                    discovered = self._parse_ffuf_output(process.stdout, domain)
                    for v in discovered:
                        v["target_ip_used"] = target_ip
                        v["bypassed_via"] = header_name # Tracciamo come è stato scoperto
                    all_discovered.extend(discovered)

                    if discovered:
                        print(f"  [+] {len(discovered)} vhost trovati su {target} (IP: {target_ip}) via {header_name}", file=sys.stderr)
                    else:
                        pass # avoid noise

                except subprocess.TimeoutExpired:
                    print(f"Timeout durante vhost enum su {target} (IP: {target_ip} Header: {header_name})", file=sys.stderr)
                except Exception as e:
                    print(f"Eccezione durante vhost enum su {target}: {str(e)}", file=sys.stderr)

        # De-duplicazione dei risultati: se un vhost è trovato tramite routing diversi,
        # lo manteniamo una sola volta (preferendo tener traccia del bypass se possibile)
        unique_vhosts = {}
        for v in all_discovered:
            k = v["vhost"]
            if k not in unique_vhosts:
                unique_vhosts[k] = v
            else:
                # Se era già stato trovato standard, e ora lo troviamo con bypass, forse vogliamo annotarlo,
                # ma per ora semplicemente non lo aggiungiamo come duplicato.
                pass
                
        final_vhosts = list(unique_vhosts.values())

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
