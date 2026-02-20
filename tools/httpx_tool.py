import json
import subprocess
import sys
import shutil
from typing import List, Dict, Any
from .base_tool import Tool

class HttpxTool(Tool):
    """
    Implementazione del tool HTTPX (ProjectDiscovery) che estende la classe base Tool.
    Esegue scansioni web su porte HTTP/HTTPS scoperte.
    """

    SCAN_PROFILES = {
        "fast": ["-title", "-status-code", "-tech-detect"],
        "comprehensive": ["-title", "-status-code", "-tech-detect", "-follow-redirects"],
        "accurate": ["-title", "-status-code", "-tech-detect", "-follow-redirects"],  # Alias per compatibilità
        "stealth": ["-title", "-status-code"],
        "noisy": ["-title", "-status-code", "-tech-detect", "-follow-redirects", "-v"]
    }

    def __init__(self):
        """
        Inizializza l'HttpxTool.
        """
        super().__init__()
        # Verifica se l'eseguibile httpx è nel PATH
        self.httpx_path = shutil.which("httpx")
        if not self.httpx_path:
            print("ATTENZIONE: Eseguibile 'httpx' non trovato nel PATH. Il tool fallirà se eseguito.", file=sys.stderr)

    def run(self, domains: List[str], params: Dict[str, Any], target_params: Dict[str, Dict] = None) -> None:
        """
        Esegue la scansione HTTPX sui target specificati.
        
        Args:
            domains (List[str]): Lista dei target (URL completi, es. http://example.com).
            params (Dict[str, Any]): Parametri della scansione.
            target_params (Dict[str, Dict]): Parametri specifici per ogni target (timing, max_rate).
        """
        if not self.httpx_path:
            for domain in domains:
                self.results[domain] = {"error": "Eseguibile httpx non trovato"}
            return
        
        if not domains:
            return
        
        # Raggruppa i target in base ai loro parametri di scansione
        param_groups = self._group_by_params(domains, target_params or {})
        
        print(f"Grouped {len(domains)} targets into {len(param_groups)} parameter groups for httpx", file=sys.stderr)
        
        # Scansiona ogni gruppo di parametri
        for group_key, group_domains in param_groups.items():
            timing, max_rate = group_key
            
            # Costruisce il comando httpx per questo gruppo
            cmd = self._build_args(params, timing, max_rate)
            
            print(f"Scanning {len(group_domains)} targets with httpx (timing={timing}, max_rate={max_rate})", file=sys.stderr)
            
            # Scansiona questo gruppo
            self._scan_group(group_domains, cmd)
    
    def _group_by_params(self, domains: List[str], target_params: Dict[str, Dict]) -> Dict[tuple, List[str]]:
        """
        Raggruppa i target in base ai loro parametri di scansione.
        Estrae il dominio base dall'URL (es. "example.com:443" -> "example.com").
        """
        groups = {}
        
        for target in domains:
            # Estrae il dominio base dall'URL (es. "example.com:443" -> "example.com")
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
        Costruisce il comando httpx basato su scan_type, timing e max_rate.
        """
        scan_type = params.get('scan_type', 'fast').lower()
        if scan_type not in self.SCAN_PROFILES:
            scan_type = 'fast'
            
        # Argomenti base
        cmd = [self.httpx_path, "-json", "-tls-grab"]
        
        # Estende con i flag del profilo selezionato
        cmd.extend(self.SCAN_PROFILES[scan_type])
        
        # Aggiunge -random-agent per stealth mode o polite timing (per evitare detection/blocking)
        if scan_type == 'stealth' or timing == 'polite':
            cmd.append("-random-agent")
        
        # Aggiunge timeout per polite timing
        if timing == 'polite':
            cmd.extend(["-timeout", "10"])
        
        # Aggiunge rate limiting
        if max_rate:
            cmd.extend(["-rate-limit", str(max_rate)])
        
        return cmd

    
    def _scan_group(self, domains: List[str], cmd: List[str]) -> None:
        """
        Scansiona un gruppo di target con lo stesso comando httpx.
        """

        # Preparazione input string (uno per riga)
        input_data = "\n".join(domains)

        try:
            # Esecuzione del processo
            process = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=False
            )
            
            if process.returncode != 0:
                print(f"Errore esecuzione httpx: {process.stderr}", file=sys.stderr)
                for target in domains:
                    if target not in self.results:  # Don't overwrite existing results
                        self.results[target] = {"error": f"Errore esecuzione httpx: {process.stderr.strip()}"}
                return

            # Parsing dell'output
            if process.stdout:
                output_lines = process.stdout.strip().split('\n')

                for line in output_lines:
                    if not line.strip():
                        continue
                    try:
                        result = json.loads(line)
                        # httpx restituisce il campo "input" o "url" utilizzabile come chiave (l'utilizzo dell'input originale come chiave è più sicuro per il mapping)
                        key = result.get("input", result.get("url"))
                        if key:
                            self.results[key] = result
                    except json.JSONDecodeError:
                        print(f"Errore parsing JSON riga httpx: {line}", file=sys.stderr)
            else:
                print("Nessun risultato ricevuto da httpx.", file=sys.stderr)
                
        except Exception as e:
            print(f"Eccezione durante esecuzione httpx: {str(e)}", file=sys.stderr)
            for target in domains:
                self.results[target] = {"error": str(e)}

    def get_results(self) -> str:
        """
        Restituisce i risultati in formato JSON.
        """
        return json.dumps(self.results, indent=4)
