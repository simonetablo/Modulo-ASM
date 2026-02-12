import json
import ipaddress
from typing import List, Dict, Any
from .base_tool import Tool

class SafetyValidatorTool(Tool):
    """
    Tool unificato per validazione IP e safety checks.
    Combina IP validation con analisi dati infrastrutturali per determinare
    se un target è sicuro da scansionare e con quali parametri.
    """
    
    def run(self, targets: List[str], params: Dict[str, Any]) -> None:
        """
        Valida target e determina safety per scansione.
        
        Args:
            targets: Lista di IP o domini da validare
            params: Deve contenere:
                - 'infrastructure_data': Risultati da HostingIntelTool (già risolti)
        """
        infra_data = params.get('infrastructure_data', {})
        domain_ip_map = params.get('domain_ip_map', {})
        
        for target in targets:
            infra = infra_data.get(target, {})
            
            # Se HostingIntelTool ha rilevato errore DNS, non c'è IP
            if infra.get('error') == 'DNS Resolution Failed':
                ip_check = {
                    "is_valid": False,
                    "is_scannable": False,
                    "reason": "Cannot resolve to IP"
                }
            else:
                # Usa IP dal mapping passato da main
                ip = domain_ip_map.get(target)
                if not ip:
                    ip_check = {
                        "is_valid": False,
                        "is_scannable": False,
                        "reason": "Cannot resolve to IP"
                    }
                else:
                    ip_check = self._validate_ip(ip)
            
            # Decision making con infra data
            self.results[target] = self._make_decision(target, ip_check, infra)
    
    def _validate_ip(self, ip_str: str) -> Dict[str, Any]:
        """Valida un singolo IP."""
        try:
            ip = ipaddress.ip_address(ip_str)
            
            result = {
                "is_valid": True,
                "ip_type": self._classify_ip(ip),
                "is_scannable": False,
                "reason": None
            }
            
            # Determina se è scansionabile
            if ip.is_global:
                result["is_scannable"] = True
            else:
                result["reason"] = self._get_non_scannable_reason(ip)
            
            return result
            
        except ValueError:
            return {
                "is_valid": False,
                "ip": ip_str,
                "ip_type": "invalid",
                "is_scannable": False,
                "reason": "Invalid IP address format"
            }
    
    def _classify_ip(self, ip: ipaddress.IPv4Address) -> str:
        """Classifica il tipo di IP."""
        if ip.is_private:
            return "private"
        elif ip.is_loopback:
            return "loopback"
        elif ip.is_link_local:
            return "link_local"
        elif ip.is_reserved:
            return "reserved"
        elif ip.is_multicast:
            return "multicast"
        elif ip.is_global:
            return "public"
        else:
            return "unknown"
    
    def _get_non_scannable_reason(self, ip: ipaddress.IPv4Address) -> str:
        """Restituisce il motivo per cui un IP non è scansionabile."""
        if ip.is_private:
            return "Private IP address"
        elif ip.is_loopback:
            return "Loopback address"
        elif ip.is_link_local:
            return "Link-local address"
        elif ip.is_reserved:
            return "Reserved IP address"
        elif ip.is_multicast:
            return "Multicast address"
        return "Non-public IP address"
    
    def _make_decision(self, target: str, ip_check: dict, infra: dict) -> Dict[str, Any]:
        """Prende decisione finale su scansionabilità."""
        skip_reasons = []
        warnings = []
        is_safe = True
        
        # Check: IP non scansionabile
        if not ip_check.get('is_scannable', False):
            is_safe = False
            skip_reasons.append(ip_check.get('reason', 'IP not scannable'))
        
        # Determina parametri di scan basati su infrastruttura
        scan_params = self._determine_scan_params(infra)
        
        return {
            "is_safe_to_scan": is_safe,
            "skip_reasons": skip_reasons,
            "warnings": warnings,
            "scan_params": scan_params,
            "ip_validation": ip_check
        }
    
    def _determine_scan_params(self, infra: dict) -> Dict[str, Any]:
        """Determina parametri di scan ottimali basati su infrastruttura."""
        params = {
            "timing": "normal",
            "max_rate": None
        }
        
        # Se è cloud/CDN, usa timing polite
        if infra.get('is_cloud') or infra.get('has_waf'):
            params['timing'] = 'polite'
            params['max_rate'] = 100
        
        return params
    
    def get_results(self) -> str:
        """Restituisce risultati in formato JSON."""
        return json.dumps(self.results, indent=4)
