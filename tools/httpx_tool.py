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

    def __init__(self):
        """
        Inizializza l'HttpxTool.
        """
        super().__init__()
        # Verifica se l'eseguibile httpx è nel PATH
        self.httpx_path = shutil.which("httpx")
        if not self.httpx_path:
            print("ATTENZIONE: Eseguibile 'httpx' non trovato nel PATH. Il tool fallirà se eseguito.", file=sys.stderr)

    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Esegue la scansione HTTPX sui target specificati.
        
        Args:
            domains (List[str]): Lista dei target (URL completi, es. http://example.com).
            params (Dict[str, Any]): Parametri della scansione.
        """
        if not self.httpx_path:
            for domain in domains:
                self.results[domain] = {"error": "Eseguibile httpx non trovato"}
            return

        # Recupera il tipo di scansione dai parametri, default a 'fast' se non specificato
        scan_type = params.get('scan_type', 'fast')
        
        # Argomenti base comuni a tutti i tipi di scansione
        base_args = ["-json"]

        # Configurazione argomenti in base al profilo
        if scan_type == 'fast':
            # -title: Estrae il titolo della pagina
            # -status-code: Mostra il codice di risposta HTTP
            # -tech-detect: Rileva le tecnologie in uso (versione base)
            profile_args = ["-title", "-status-code", "-tech-detect"]
        elif scan_type == 'accurate':
            # -title: Estrae il titolo
            # -status-code: Codice HTTP
            # -tech-detect: Rileva tecnologie
            # -follow-redirects: Segue i reindirizzamenti
            # -random-agent: Usa User-Agent casuali per evitare blocchi semplici
            profile_args = ["-title", "-status-code", "-tech-detect", "-follow-redirects", "-random-agent"]
        elif scan_type == 'stealth':
            # -title: Titolo pagina
            # -status-code: Codice HTTP
            # -random-agent: User-Agent casuale
            profile_args = ["-title", "-status-code", "-random-agent"]
        else:
            # Fallback al profilo 'fast' per tipi di scan non riconosciuti
            profile_args = ["-title", "-status-code", "-tech-detect"]

        if not domains:
            return

        # Costruzione del comando completo. I target vengono passati via stdin per efficienza e concorrenza
        cmd = [self.httpx_path] + base_args + profile_args
        
        # Preparazione input string (uno per riga)
        input_data = "\n".join(domains)
        
        try:
            print(f"Avvio scansione HTTPX su {len(domains)} target con profilo '{scan_type}'", file=sys.stderr)
            
            # Esecuzione del processo unico
            process = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=False 
            )
            
            if process.returncode != 0:
                print(f"Errore esecuzione httpx globale: {process.stderr}", file=sys.stderr)
                # In caso di crash globale, segna errore su tutti i domini non ancora processati
                for target in domains:
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
