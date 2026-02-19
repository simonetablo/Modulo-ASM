import json
import subprocess
import sys
import socket
import shutil
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
        "comprehensive": {
            "threads": 80,
            "flags": ["-ac", "-mc", "all", "-t", "80", "-timeout", "10"]
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

    def __init__(self):
        """
        Inizializza il VhostEnumTool.
        Verifica la presenza di ffuf nel PATH.
        """
        super().__init__()
        self.ffuf_path = shutil.which("ffuf")
        if not self.ffuf_path:
            print("ATTENZIONE: Eseguibile 'ffuf' non trovato nel PATH. Il tool fallirà se eseguito.", file=sys.stderr)

    def run(self, domains: List[str], params: Dict[str, Any], target_params: Dict[str, Dict] = None) -> None:
        """
        Esegue il virtual host enumeration sui target web specificati.
        
        Args:
            domains (List[str]): Lista dei target web (formato 'dominio:porta').
            params (Dict[str, Any]): Parametri della scansione (scan_type, wordlist).
            target_params (Dict[str, Dict]): Parametri specifici per ogni target (timing, max_rate).
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
                self._scan_target(target, base_args, wordlist)

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

    def _scan_target(self, target: str, base_args: List[str], wordlist: str) -> None:
        """
        Esegue il vhost enumeration su un singolo target.
        
        Risolve il dominio a IP e configura ffuf per fuzzare l'header Host:
        inviando richieste all'IP con header Host: FUZZ.<dominio_base>

        Args:
            target: Target nel formato 'dominio:porta'
            base_args: Argomenti ffuf base costruiti da _build_args
            wordlist: Percorso alla wordlist per il fuzzing
        """
        # Parsing del target: dominio:porta
        parts = target.split(':')
        domain = parts[0]
        port = parts[1] if len(parts) > 1 else "80"

        # Risoluzione DNS
        try:
            target_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"ERRORE: Impossibile risolvere {domain} per vhost enumeration", file=sys.stderr)
            self.results[target] = {"error": f"Impossibile risolvere il dominio {domain}"}
            return

        # Determina schema
        scheme = "https" if port in ("443", "8443") else "http"

        # Costruisce URL target (verso l'IP)
        target_url = f"{scheme}://{target_ip}:{port}/"

        # Costruisce il comando ffuf completo
        cmd = list(base_args)  # Copia per non modificare gli args condivisi
        cmd.extend([
            "-u", target_url,
            "-H", f"Host: FUZZ.{domain}",
            "-w", wordlist
        ])

        print(f"VHost enum su {domain} ({target_ip}:{port}) - schema: {scheme}", file=sys.stderr)

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=120  # Timeout di 2 minuti per target
            )

            if process.returncode != 0 and not process.stdout:
                error_msg = process.stderr.strip() if process.stderr else f"ffuf exit code: {process.returncode}"
                print(f"Errore ffuf su {target}: {error_msg}", file=sys.stderr)
                self.results[target] = {"error": f"Errore ffuf: {error_msg}"}
                return

            # Parsing risultati
            discovered_vhosts = self._parse_ffuf_output(process.stdout, domain)
            self.results[target] = {
                "target_ip": target_ip,
                "domain": domain,
                "port": port,
                "discovered_vhosts": discovered_vhosts,
                "count": len(discovered_vhosts)
            }

            if discovered_vhosts:
                print(f"  [+] {len(discovered_vhosts)} vhost trovati su {target}", file=sys.stderr)
            else:
                print(f"  [-] Nessun vhost trovato su {target}", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print(f"Timeout durante vhost enum su {target}", file=sys.stderr)
            self.results[target] = {"error": "Timeout (120s) durante esecuzione ffuf"}
        except Exception as e:
            print(f"Eccezione durante vhost enum su {target}: {str(e)}", file=sys.stderr)
            self.results[target] = {"error": str(e)}

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
