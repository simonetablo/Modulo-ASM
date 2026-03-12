import json
import subprocess
import sys
import shutil
from typing import List, Dict, Any
from .base_tool import Tool, BASE_DIR

class HttpxTool(Tool):
    """
    Implementazione del tool HTTPX (ProjectDiscovery) che estende la classe base Tool.
    Esegue scansioni web su porte HTTP/HTTPS scoperte.
    Parametri caricati da config/httpx/<scan_type>_config.json.
    """

    # Defaults hardcoded come ultimo fallback se nessun file config è presente
    DEFAULT_CONFIG = {
        "flags": ["-title", "-status-code", "-tech-detect", "-favicon", "-hash", "sha256"],
        "polite_timeout": 10,
        "verify_threads": 150,
        "verify_timeout": 5,
        "verify_match_codes": "100-403,405-599",
        "process_timeout_per_url": 10,
        "process_timeout_buffer": 300
    }

    def __init__(self):
        """
        Inizializza l'HttpxTool.
        """
        super().__init__()
        # Inizializza config con default (Fix #11)
        self._config = self.DEFAULT_CONFIG.copy()
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
            
            domain_params = target_params.get(base_domain, {})
            timing = domain_params.get('timing', 'normal')
            max_rate = domain_params.get('max_rate')
            
            key = (timing, max_rate)
            if key not in groups:
                groups[key] = []
            groups[key].append(target)
        
        return groups
    
    def _build_args(self, params: Dict[str, Any], timing: str, max_rate: int = None) -> List[str]:
        """
        Costruisce il comando httpx basato su config file, timing e max_rate.
        """
        scan_type = params.get('scan_type', 'fast').lower()
        
        # Carica configurazione da file con fallback chain
        file_config = self.load_config("httpx", scan_type)
        self._config = {**self.DEFAULT_CONFIG, **file_config}
            
        # Argomenti base
        cmd = [self.httpx_path, "-json", "-tls-grab"]
        
        # Estende con i flag dal config
        cmd.extend(self._config["flags"])
        
        # Aggiunge -random-agent per stealth mode o polite timing (per evitare detection/blocking)
        if scan_type == 'stealth' or timing == 'polite':
            cmd.append("-random-agent")
        
        # Aggiunge timeout per polite timing
        if timing == 'polite':
            cmd.extend(["-timeout", str(self._config.get("polite_timeout", 10))])
        
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
                check=False,
                timeout=(len(domains) * self._config.get("process_timeout_per_url", 10)) + self._config.get("process_timeout_buffer", 300)
            )
            
            # Trova errori critici
            if process.returncode != 0 and not process.stdout.strip():
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

    def verify_urls(self, urls: List[str], headers: Dict[str, str] = None) -> List[str]:
        """
        Valida una lista di URL controllando se sono vivi (status 2xx/3xx).
        Usa un profilo super-veloce di httpx.
        
        Args:
            urls (List[str]): Lista di URL da verificare.
            headers (Dict[str, str]): Eventuali header da aggiungere alla verifica.
            
        Returns:
            List[str]: Lista di URL che hanno risposto positivamente.
        """
        if not self.httpx_path or not urls:
            return []

        # Carica config per i parametri di verify (Fix #12)
        config = {**self.DEFAULT_CONFIG, **self.load_config("httpx")}
        
        verify_threads = str(config.get("verify_threads", 150))
        verify_timeout = str(config.get("verify_timeout", 5))
        verify_match_codes = config.get("verify_match_codes", "100-403,405-599")
        
        cmd = [
            self.httpx_path,
            "-silent",
            "-nc",
            "-t", verify_threads, 
            "-timeout", verify_timeout,
            "-mc", verify_match_codes,
            "-follow-redirects"
        ]

        # Aggiunta Header custom se forniti
        if headers:
            for h_name, h_val in headers.items():
                cmd.extend(["-H", f"{h_name}: {h_val}"])

        verified = []
        input_data = "\n".join(urls)

        try:
            # Eseguiamo httpx in modo che restituisca solo le URL che matchano i codici
            process = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=False,
                timeout=(len(urls) // 10) + 60
            )

            if process.stdout:
                # httpx restituisce una lista di URL (una per riga)
                for line in process.stdout.strip().split('\n'):
                    if line.strip():
                        verified.append(line.strip())
        except Exception as e:
            print(f"Errore durante verify_urls: {e}", file=sys.stderr)

        return list(set(verified))

    def get_results(self) -> str:
        """
        Restituisce i risultati in formato JSON.
        """
        return json.dumps(self.results, indent=4)
