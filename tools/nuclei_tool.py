import json
import subprocess
import os
import shutil
import sys
from typing import List, Dict, Any
from .base_tool import Tool

class NucleiTool(Tool):
    """
    Implementazione del tool Nuclei (ProjectDiscovery).
    Esegue scansioni di fingerprinting avanzato e vulnerability scanning su risorse web (URL).
    """

    # Definizione dei profili di scansione. In ASM ci concentriamo su info-gathering e misconfigurations.
    SCAN_PROFILES = {
        "fast": ["-tags", "tech,exposure", "-severity", "info,low", "-c", "50", "-bs", "50"],
        "accurate": ["-tags", "tech,exposure,config", "-severity", "info,low,medium", "-c", "25", "-bs", "25"],
        "comprehensive": ["-tags", "tech,exposure,config,misconfig,takeover", "-c", "100", "-bs", "100"],
        "stealth": ["-tags", "tech,exposure", "-severity", "info", "-rl", "50", "-c", "2", "-timeout", "10"],
        "noisy": ["-tags", "tech,exposure,config,cve,default-login,fuzz", "-c", "150", "-bs", "150"]
    }

    def __init__(self):
        """
        Inizializza il NucleiTool.
        """
        super().__init__()
        self.results = {}
        
        # Verifica se l'eseguibile nuclei è nel PATH
        self.nuclei_path = shutil.which("nuclei")
        if not self.nuclei_path:
            print("ATTENZIONE: Eseguibile 'nuclei' non trovato nel PATH. Il tool fallirà se eseguito.", file=sys.stderr)
            print("Installalo con: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", file=sys.stderr)

    def run(self, targets: List[str], params: Dict[str, Any], target_params: Dict[str, Dict] = None) -> None:
        """
        Esegue la scansione Nuclei sui target web specificati.
        
        Args:
            targets (List[str]): Lista degli URL target (es. http://example.com:8080).
            params (Dict[str, Any]): Parametri della scansione globali.
            target_params (Dict[str, Dict]): Parametri specifici per ogni target base_domain.
        """
        if not self.nuclei_path:
            for url in targets:
                self.results[url] = {"error": "Eseguibile nuclei non trovato nel sistema"}
            return
            
        if not targets:
            return

        # Raggruppa i target in base ai loro parametri di scansione
        param_groups = self._group_by_params(targets, target_params or {})
        
        print(f"Grouped {len(targets)} URLs into {len(param_groups)} parameter groups for Nuclei", file=sys.stderr)
        
        # Scansiona ogni gruppo di parametri
        for group_key, group_targets in param_groups.items():
            timing, max_rate = group_key
            
            # Recupera il profilo di scansione principale per costruire i comandi
            scan_type = params.get('scan_type', 'fast').lower()
            cmd = self._build_args(scan_type, timing, max_rate)
            
            print(f"Avvio scansione Nuclei su {len(group_targets)} web targets (profilo: {scan_type})", file=sys.stderr)
            
            # Scansiona questo gruppo
            self._scan_group(group_targets, cmd)

    def _group_by_params(self, targets: List[str], target_params: Dict[str, Dict]) -> Dict[tuple, List[str]]:
        """
        Raggruppa i target URL in base ai loro parametri di scansione.
        Estrae il dominio base dall'URL (es. "http://example.com:443" -> "example.com").
        """
        groups = {}
        
        for url in targets:
            # Estrae il dominio base dall'URL per cercare le configurazioni specifiche in target_params
            clean_url = url.replace('http://', '').replace('https://', '')
            base_domain = clean_url.split('/')[0].split(':')[0]
            
            params = target_params.get(base_domain, {})
            timing = params.get('timing', 'normal')
            max_rate = params.get('max_rate')
            
            key = (timing, max_rate)
            if key not in groups:
                groups[key] = []
            groups[key].append(url)
        
        return groups

    def _build_args(self, scan_type: str, timing: str, max_rate: int = None) -> List[str]:
        """
        Costruisce il comando nuclei basato su scan_type, timing e max_rate.
        """
        if scan_type not in self.SCAN_PROFILES:
            scan_type = 'fast'
            
        cmd = [self.nuclei_path, "-jsonl", "-silent", "-nc", "-ni"] # -ni disabled automatic update check
        
        cmd.extend(self.SCAN_PROFILES[scan_type])
        
        # Aggiunge timeout e rate limit per polite/stealth timing per ridurre il rischio di drop WAF
        if timing == 'polite':
            cmd.extend(["-rl", "20", "-timeout", "10"])
        
        if max_rate:
            cmd.extend(["-rl", str(max_rate)])
            
        return cmd

    def _scan_group(self, targets: List[str], cmd: List[str]) -> None:
        """
        Scansiona un gruppo di URLs con il comando nuclei configurato.
        Raccoglie l'output JSON riga per riga per associarlo ai singoli target.
        """
        # Preparazione lista target via stdin (uno per riga)
        input_data = "\n".join(targets)

        try:
            # Esecuzione del processo Nuclei in subshell
            process = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Se ha stampato uno stderr ma ha restituito risultati ignoriamo perché Nuclei logga molto
            # print(f"DEBUG NUCLEI STDERR: {process.stderr}", file=sys.stderr)

            # Inizializza un array vuoto per ogni target
            for url in targets:
                if url not in self.results:
                    self.results[url] = []

            # Parsing dell'output standard (righe JSON)
            if process.stdout:
                output_lines = process.stdout.strip().split('\n')
                count_findings = 0
                
                for line in output_lines:
                    if not line.strip() or not line.startswith('{'):
                        continue
                        
                    try:
                        record = json.loads(line)
                        matched_url = record.get("host") 
                        
                        # Cerca il target originale più simile all'URL testato perché Nuclei potrebbe droppare
                        # lo schema o aggiungere trailing slashes nel campo "host" o "matched-at"
                        target_key = None
                        
                        # 1. Prova match esatto
                        if matched_url in self.results:
                            target_key = matched_url
                        else:
                            # 2. Prova match inclusivo o di fallback estraendo l'host
                            for original_target in targets:
                                if matched_url and (matched_url in original_target or original_target in matched_url):
                                    target_key = original_target
                                    break
                        
                        if target_key:
                            # Estrae solo i dati salienti e riduce lo spazio del report finale dell'ASM
                            finding = {
                                "id": record.get("template-id", "unknown"),
                                "name": record.get("info", {}).get("name", "Unknown vulnerability or technology"),
                                "severity": record.get("info", {}).get("severity", "info"),
                                "matched_at": record.get("matched-at", ""),
                                "description": record.get("info", {}).get("description", "")
                            }
                            # Opzionale: aggiunge tags per categorizzare
                            tags = record.get("info", {}).get("tags", [])
                            if tags:
                                finding["tags"] = tags
                                
                            self.results[target_key].append(finding)
                            count_findings += 1
                        else:
                            print(f"ATTENZIONE: Nuclei result non mappabile a target noti: {matched_url}", file=sys.stderr)
                            
                    except json.JSONDecodeError:
                        # Ignora righe non JSON
                        pass
                        
                print(f"Nuclei: Trovati {count_findings} matching complessivi per {len(targets)} URLs.", file=sys.stderr)
            else:
                print("Nessun match identificato da Nuclei in questo gruppo.", file=sys.stderr)
                
        except Exception as e:
            print(f"Eccezione durante esecuzione Nuclei: {str(e)}", file=sys.stderr)
            for url in targets:
                # Se l'array è vuoto sovrascrive con errore
                if not self.results.get(url):
                    self.results[url] = {"error": str(e)}

    def get_results(self) -> str:
        """
        Restituisce i risultati in formato JSON formattato.
        """
        return json.dumps(self.results, indent=4)
