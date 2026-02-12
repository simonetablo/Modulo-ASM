import socket
import json
import sys
import dns.resolver
from ipwhois import IPWhois, IPDefinedError
from typing import List, Dict, Any
from .base_tool import Tool

class HostingIntelTool(Tool):
    """
    Tool per l'analisi dell'infrastruttura che ospita gli IP target.
    Utilizza ipwhois per ASN/Org lookup e Cloud/CDN detection.
    """

    def __init__(self):
        super().__init__()
        self.cloud_keywords = self._load_cloud_keywords()
    
    def _load_cloud_keywords(self) -> dict:
        """Carica cloud keywords da file config con fallback a defaults."""
        import os
        
        # Path al file di configurazione
        config_path = os.path.join(
            os.path.dirname(__file__), 
            'config', 
            'cloud_providers.json'
        )
        
        # Fallback hardcoded se file non esiste
        default_keywords = {
            "amazon": "Amazon AWS",
            "google": "Google Cloud",
            "microsoft": "Microsoft Azure",
            "azure": "Microsoft Azure",
            "cloudflare": "Cloudflare",
            "fastly": "Fastly CDN",
            "akamai": "Akamai CDN",
            "digitalocean": "DigitalOcean",
            "linode": "Linode",
            "oracle": "Oracle Cloud",
            "alibaba": "Alibaba Cloud",
            "hetzner": "Hetzner Cloud",
            "ovh": "OVH Cloud",
            "herokuapp": "Heroku"
        }
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config.get('providers', default_keywords)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Unable to load cloud config ({e}). Using defaults.", file=sys.stderr)
            return default_keywords

    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Esegue l'analisi infrastrutturale sugli IP dei domini elencati.
        """
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
        
        # Analisi per ogni IP univoco
        ip_results = {}
        for ip in ips_to_analyze:
            ip_results[ip] = self._analyze_ip(ip)
            
        # Mappa i risultati ai target originali e aggiungi check IP rotation
        for target in domains:
            if target in self.results and "error" in self.results[target]:
                continue
                
            ip = domain_ip_map.get(target)
            if ip and ip in ip_results:
                self.results[target] = ip_results[ip].copy()
                # Check per IP dinamici/rotanti
                rotation_info = self._check_ip_rotation(target)
                self.results[target].update(rotation_info)
        
        # Salva mapping IP per uso downstream (non fa parte di infrastructure data)
        self.results['_ip_map'] = domain_ip_map
    
    def _check_ip_rotation(self, domain: str) -> Dict[str, Any]:
        """
        Verifica se il dominio usa IP dinamici/rotanti.
        Usa TTL e numero di A record come indicatori.
        """
        
        result = {
            "is_dynamic": False,
            "ttl": None,
            "ip_pool_size": 1
        }
        
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, 'A')

            # Estrai TTL e numero di IP nel pool
            result["ttl"] = answers.rrset.ttl
            result["ip_pool_size"] = len(answers)
            
            # Euristica per IP dinamici:
            # - TTL < 60s = rotazione frequente (CDN/load balancer)
            # - Pool size > 1 = multiple IP available
            if result["ttl"] < 60 or result["ip_pool_size"] > 1:
                result["is_dynamic"] = True
                
        except Exception as e:
            # Se DNS query fallisce, assume statico
            # print(f"DEBUG DNS Error for {domain}: {e}", file=sys.stderr)
            pass
        
        return result

    def _analyze_ip(self, ip: str) -> Dict[str, Any]:
        """
        Esegue i check specifici su un singolo IP.
        """
        result = {
            "is_cloud": False,
            "cloud_provider": None,
            "asn": None,
            "org": None
        }
        
        # ASN/Org Lookup via IPWhois (Cloud/CDN Detection)
        try:
            obj = IPWhois(ip)
            rdap_result = obj.lookup_rdap(depth=1)
            
            asn_desc = rdap_result.get('asn_description', '')
            asn_org = rdap_result.get('network', {}).get('name', '')
            
            result["asn"] = rdap_result.get('asn')
            result["org"] = asn_org
            
            # Analisi keyword su ASN Description e Network Name
            full_desc = (str(asn_desc) + " " + str(asn_org)).lower()
            
            for keyword, provider in self.cloud_keywords.items():
                if keyword in full_desc:
                    result["is_cloud"] = True
                    result["cloud_provider"] = provider
                    break
                    
        except IPDefinedError:
            # IP privati o riservati
            result["org"] = "Private/Reserved IP"
            result["asn"] = "NA"
            
        except Exception as e:
            # Altri errori di lookup
            # print(f"Errore IPWhois per {ip}: {e}", file=sys.stderr)
            pass
        
        return result

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
