import socket
import json
import sys
import subprocess
import shutil
import dns.resolver
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
        
        print(f"Avvio analisi infrastruttura su {len(domains)} target...", file=sys.stderr)

        for target in domains:
            # Risolve dominio in IP
            try:
                ip = socket.gethostbyname(target)
                ips_to_analyze.add(ip)
                domain_ip_map[target] = ip
            except socket.gaierror:
                print(f"Errore: Impossibile risolvere {target} per analisi infrastruttura", file=sys.stderr)
                self.results[target] = {"error": "DNS Resolution Failed"}
                continue
        
        if not ips_to_analyze:
            return

        # Esecuzione di cdncheck sugli IP unici
        print(f"Esecuzione di cdncheck su {ips_to_analyze}", file=sys.stderr)
        ip_results = self._run_cdncheck(list(ips_to_analyze))
            
        # Mappa i risultati ai target originali e aggiungi check IP rotation
        for target in domains:
            if target in self.results and "error" in self.results[target]:
                continue
                
            ip = domain_ip_map.get(target)
            if ip:
                # Recupera info da cdncheck, default a {} se non trovato
                self.results[target] = ip_results.get(ip, {
                    "is_cloud": False, 
                    "type": "unknown"
                })
                
                # Check per IP dinamici/rotanti
                rotation_info = self._check_ip_rotation(target)
                self.results[target].update(rotation_info)
        
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
    
    def _check_ip_rotation(self, domain: str) -> Dict[str, Any]:
        """
        Verifica euristicamente se il dominio usa IP dinamici/rotanti.
        Usa TTL e numero di A record come indicatori.
        """
        
        result = {
            "is_dynamic": False,
            "ttl": None,
            "ip_pool_size": 1
        }
        
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = self.dns_resolvers
            resolver.timeout = 5
            resolver.lifetime = 5

            
            answers = resolver.resolve(domain, 'A')

            # Estrai TTL e numero di IP nel pool
            result["ttl"] = answers.rrset.ttl
            result["ip_pool_size"] = len(answers)
            
            # Euristica per IP dinamici:
            # - TTL < 300s = rotazione frequente (CDN/load balancer)
            # - Pool size > 1 = multiple IP available
            if result["ttl"] < 300 or result["ip_pool_size"] > 1:
                result["is_dynamic"] = True
                
        except Exception as e:
            # Se DNS query fallisce, assume statico
            # print(f"DEBUG DNS Error for {domain}: {e}", file=sys.stderr)
            pass
        
        return result

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
