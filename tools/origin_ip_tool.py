import sys
import json
from typing import List, Dict, Any
from urllib.parse import urlparse
from .base_tool import Tool

class OriginIpTool(Tool):
    """
    Tool per identificare potenziali Origin IPs (IP reali dei server)
    dietro CDN o WAF (Cloudflare, Akamai, ecc.).
    
    Analizza i domini scoperti e le informazioni infrastrutturali:
    Se il dominio principale è dietro CDN, ma alcuni sottodomini risolvono 
    su IP che NON appartengono a CDN, quegli IP vengono classificati come 
    potenziali Origin IPs.
    """

    def __init__(self, dns_resolvers: List[str] = None):
        super().__init__()
        self.results = {}
        self.dns_resolvers = dns_resolvers or ['1.1.1.1', '8.8.8.8']

    def run(self, params: Dict[str, Any], infra_results: Dict[str, Any] = None, grouped_domains: Dict[str, List[str]] = None) -> None:
        """
        Analizza i domini e l'infrastruttura per trovare gli Origin IPs.
        
        Args:
            params (Dict[str, Any]): Parametri (non strettamente necessari qui).
            infra_results (Dict[str, Any]): Risultati da HostingIntelTool (mapping dominio/IP -> info infra).
            grouped_domains (Dict[str, List[str]]): Dizionario Domini Base -> Sottodomini.
        """
        if not infra_results or "_ip_map" not in infra_results:
            print("OriginIpTool: Nessun mapping dominio-IP fornito (manca _ip_map).", file=sys.stderr)
            return
            
        if not grouped_domains:
            print("OriginIpTool: Nessun raggruppamento domini fornito.", file=sys.stderr)
            return

        domain_ip_map = infra_results.get("_ip_map", {})
        domains_count = sum(len(subs) for subs in grouped_domains.values())

        print(f"Avvio ricerca Origin IPs su {domains_count} target...", file=sys.stderr)

        # Mettiamo in relazione domini base con tutti i loro IP e dati infra
        
        for base_domain, subdomains in grouped_domains.items():
            self.results[base_domain] = {"origin_ips": [], "cdn_ips": [], "is_behind_cdn": False}
            
            origin_candidates = set()
            cdn_ips = set()
            
            # Controlliamo il base_domain
            base_infra = infra_results.get(base_domain, {})
            is_base_cdn = self._is_cdn(base_infra)
            if is_base_cdn:
                self.results[base_domain]["is_behind_cdn"] = True
                
            # Recuperiamo l'IP map da infra_results per avere l'IP del dominio
            # Lo passo tramite params o uso una logica di risoluzione semplice
            # Per semplificare assumiamo che infra_results possa avere il dato o iteriamo su subdomains
            
            # Usiamo domain_ip_map esposto sopra
            for sub in subdomains:
                sub_infra = infra_results.get(sub, {})
                ip = domain_ip_map.get(sub)
                
                if not ip:
                    continue
                    
                # Controlliamo se QUESTO IP è una CDN consultando infra_results tramite l'IP
                ip_infra = infra_results.get(ip, sub_infra) # fallback su sub_infra
                
                if self._is_cdn(ip_infra):
                    cdn_ips.add(ip)
                else:
                    # Se non ha infrastruttura CDN, è un potenziale Origin IP!
                    origin_candidates.add(ip)
                    
            # Salviamo i risultati per il dominio base
            self.results[base_domain]["origin_ips"] = list(origin_candidates)
            self.results[base_domain]["cdn_ips"] = list(cdn_ips)
            
            if self.results[base_domain]["is_behind_cdn"] and origin_candidates:
                print(f"  [!] {base_domain} usa CDN. Trovati {len(origin_candidates)} potenziali Origin IPs "
                      f"(es. {list(origin_candidates)[:2]}) nei sottodomini.", file=sys.stderr)



    def _is_cdn(self, infra_data: Dict[str, Any]) -> bool:
        """Controlla se i dati indicano presenza di CDN/WAF/Cloud Router"""
        if not infra_data:
             return False
        return infra_data.get("has_infrastructure", False)

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
