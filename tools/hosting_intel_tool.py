import json
import sys
import subprocess
import shutil
import random
import dns.resolver
import dns.exception
import concurrent.futures
from typing import List, Dict, Any
from .base_tool import Tool

class HostingIntelTool(Tool):
    """
    Tool per l'analisi dell'infrastruttura che ospita gli IP target.
    Utilizza 'cdncheck' (ProjectDiscovery) per identificare Cloud/CDN/WAF.
    """

    def __init__(self, dns_resolvers: List[str] = None):
        """
        Inizializza il tool con DNS resolvers configurabili.
        
        Args:
            dns_resolvers: Lista di DNS resolver IPs. Default: ['1.1.1.1', '8.8.8.8', '8.8.4.4']
        """
        super().__init__()
        self.dns_resolvers = dns_resolvers or ['1.1.1.1', '8.8.8.8', '8.8.4.4']
        self.results = {}
        
        # Verifica se l'eseguibile cdncheck è nel PATH
        self.cdncheck_path = shutil.which("cdncheck")
        if not self.cdncheck_path:
            print("ATTENZIONE: Eseguibile 'cdncheck' non trovato nel PATH. Il tool fallirà se eseguito.", file=sys.stderr)
            print("Installalo con: go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", file=sys.stderr)


    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Esegue l'analisi infrastrutturale sugli IP dei domini elencati usando cdncheck.
        """
        if not self.cdncheck_path:
            for target in domains:
                self.results[target] = {"error": "Eseguibile cdncheck non trovato"}
            return

        ips_to_analyze = set()
        domain_ip_map = {} # Mappa dominio -> IP
        domain_dns_info = {} # Mappa dominio -> {"ttl": ..., "pool_size": ...}
        
        scan_type = params.get("scan_type", "fast").lower()

        # Determina fallback e timeout in base al profilo di scansione
        if scan_type == "fast":
            fallback_count = min(2, len(self.dns_resolvers))
            timeout_sec = 2.0
        elif scan_type == "stealth":
            fallback_count = min(1, len(self.dns_resolvers))
            timeout_sec = 10.0
        elif scan_type == "accurate":
            fallback_count = min(3, len(self.dns_resolvers))
            timeout_sec = 5.0
        elif scan_type == "comprehensive":
            fallback_count = min(4, len(self.dns_resolvers))
            timeout_sec = 8.0
        else:
            fallback_count = min(2, len(self.dns_resolvers))
            timeout_sec = 2.0
            
        print(f"Avvio analisi infrastruttura su {len(domains)} target (fallback={fallback_count}, timeout={timeout_sec}s)...", file=sys.stderr)

        # Helper interno per multi-threading delle query DNS
        def resolve_domain(target):
            try:
                resolver = dns.resolver.Resolver(configure=False)
                # Selezione randomica/round-robin per load balancing e fail-fast
                resolver.nameservers = random.sample(self.dns_resolvers, fallback_count) if self.dns_resolvers else ['8.8.8.8']
                resolver.timeout = timeout_sec
                resolver.lifetime = timeout_sec * fallback_count
                
                answers = resolver.resolve(target, 'A')
                ip = str(answers[0]) # Prende il primo record A
                ttl = answers.rrset.ttl
                pool_size = len(answers)
                return target, ip, ttl, pool_size, None
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
                return target, None, None, None, "DNS Resolution Failed"
            except Exception:
                return target, None, None, None, "DNS Resolution Failed"

        max_workers = min(50, len(domains) if domains else 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {executor.submit(resolve_domain, target): target for target in domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                target, ip, ttl, pool_size, error = future.result()
                if error:
                    self.results[target] = {"error": error}
                else:
                    ips_to_analyze.add(ip)
                    domain_ip_map[target] = ip
                    domain_dns_info[target] = {"ttl": ttl, "pool_size": pool_size}
        
        if not ips_to_analyze:
            return

        # Esecuzione di cdncheck sugli IP unici
        print(f"Esecuzione di cdncheck su {ips_to_analyze}", file=sys.stderr)
        ip_results = self._run_cdncheck(list(ips_to_analyze))
            
        # Mappa i risultati ai target originali e aggiungi check IP rotation
        def process_target_rotation(target):
            if target in self.results and "error" in self.results[target]:
                return target, None
                
            ip = domain_ip_map.get(target)
            if not ip:
                return target, None
                
            # Recupera info da cdncheck, default a {} se non trovato
            info = ip_results.get(ip, {
                "has_infrastructure": False,
                "type_details": {}
            })
            # Recupera dati DNS salvati
            dns_data = domain_dns_info.get(target, {})
            # Check per IP dinamici/rotanti usando i dati DNS già risolti
            rotation_info = self._check_ip_rotation(target, dns_data.get("ttl"), dns_data.get("pool_size"))
            info.update(rotation_info)
            return target, info

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(process_target_rotation, target): target for target in domains}
            for future in concurrent.futures.as_completed(future_to_target):
                target, info = future.result()
                if info is not None:
                    self.results[target] = info
        
        # Salva mapping IP per uso downstream
        self.results['_ip_map'] = domain_ip_map

    def _run_cdncheck(self, ips: List[str]) -> Dict[str, Any]:
        """
        Esegue cdncheck su una lista di IP e restituisce un dizionario {ip: info}.
        """
        results = {}
        
        # cdncheck accetta IP via stdin e restituisce JSON con -j (o -json nelle versioni che lo supportano)
        cmd = [self.cdncheck_path, "-j"]
        
        input_data = "\n".join(ips)
        try:
            process = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Nota: cdncheck potrebbe scrivere banner su stdout/stderr. Vengono filtrate le righe che sembrano JSON validi.

            # Parsing output JSON (una linea per risultato)
            for line in process.stdout.strip().split('\n'):
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                try:
                    data = json.loads(line)
                    ip = data.get("ip")
                    if not ip:
                        continue
                        
                    # Detect all infrastructure types and their providers
                    type_details = {}
                    
                    if data.get("cdn"):
                        type_details["cdn"] = data.get("cdn_name", "Unknown").title()
                    
                    if data.get("cloud"):
                        type_details["cloud"] = data.get("cloud_name", "Unknown").title()
                    
                    if data.get("waf"):
                        type_details["waf"] = data.get("waf_name", "Unknown").title()
                    
                    # Indicates if any special infrastructure is detected (CDN/Cloud/WAF)
                    has_infrastructure = len(type_details) > 0
                    
                    results[ip] = {
                        "has_infrastructure": has_infrastructure,
                        "type_details": type_details  # {"cdn": "Cloudflare", "waf": "Cloudflare"}
                    }
                    
                except json.JSONDecodeError:
                    pass # Ignora righe non-JSON (banner, log, ecc.)

        except Exception as e:
            print(f"Eccezione durante esecuzione cdncheck: {str(e)}", file=sys.stderr)
            
        return results
    
    def _check_ip_rotation(self, domain: str, ttl: int = None, pool_size: int = None) -> Dict[str, Any]:
        """
        Analisi avanzata della rotazione IP.
        Usa TTL e numero di A record come indicatori, recuperati dalla query DNS principale.
        """
        
        result = {
            "is_dynamic": False,
            "ttl": ttl,
            "ip_pool_size": pool_size or 1
        }
        
        if ttl is not None and pool_size is not None:
            # Euristica per IP dinamici:
            # - TTL < 300s = rotazione frequente (CDN/load balancer)
            # - Pool size > 1 = multiple IP available
            if ttl < 300 or pool_size > 1:
                result["is_dynamic"] = True
                
        return result

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
