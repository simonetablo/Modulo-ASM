import nmap
import json
import sys
import socket
from typing import List, Dict, Any
from .base_tool import Tool

class NmapTool(Tool):
    """
    Implementazione del tool Nmap che estende la classe base Tool.
    Utilizza la libreria `python-nmap` per eseguire scansioni di rete.
    """

    SCAN_PROFILES = {
        "fast": "-F",
        "comprehensive": "-p- -sV -sC -o",
        "accurate": "-p- -sV -sC -o",
        "stealth": "-sS",
        "noisy": "-p- -T5 -o --script default,discovery,safe"
    }

    def __init__(self):
        """
        Inizializza il NmapTool.
        Chiama il costruttore della superclasse e inizializza l'oggetto PortScanner di nmap.
        """
        super().__init__()
        # Inizializza l'oggetto PortScanner dalla libreria nmap, fondamentale per interagire con l'eseguibile nmap installato nel sistema
        try:
            self.nm = nmap.PortScanner()
            # DEBUG: Verifica che nmap sia stato trovato correttamente
            nmap_version = self.nm.nmap_version()
            print(f"DEBUG: Nmap trovato. Versione: {nmap_version}", file=sys.stderr)
        except nmap.PortScannerError:
            print("ERRORE: Nmap non trovato nel PATH.", file=sys.stderr)
            print("Assicurati che nmap sia installato e aggiunto al PATH di sistema.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Errore inatteso nell'inizializzazione di nmap: {e}", file=sys.stderr)
            sys.exit(1)

    def run(self, domains: List[str], params: Dict[str, Any], target_params: Dict[str, Dict] = None) -> None:
        """
        Esegue la scansione Nmap sui domini specificati.
        Configura gli argomenti di Nmap in base al parametro 'scan_type' e parametri per-target.

        Args:
            domains (List[str]): Lista dei domini target.
            params (Dict[str, Any]): Parametri della scansione. Si aspetta una chiave 'scan_type'
                                     che può essere 'fast', 'accurate' o 'stealth'.
            target_params (Dict[str, Dict]): Parametri specifici per ogni target (timing, max_rate).
        """
        # Raggruppa i domini in base ai loro parametri di scansione
        param_groups = self._group_by_params(domains, target_params or {})
        
        print(f"Grouped {len(domains)} domains into {len(param_groups)} parameter groups for nmap", file=sys.stderr)
        
        # Scansiona ogni gruppo di parametri
        for group_key, group_domains in param_groups.items():
            timing, max_rate = group_key
            
            # Costruisce gli argomenti nmap per questo gruppo
            args = self._build_args(params.get('scan_type', 'fast'), timing, max_rate)
            
            print(f"Scanning {len(group_domains)} domains with timing={timing}, max_rate={max_rate}", file=sys.stderr)
            
            # Scansiona ogni dominio nel gruppo con gli stessi parametri
            self._scan_group(group_domains, args)
    
    def _group_by_params(self, domains: List[str], target_params: Dict[str, Dict]) -> Dict[tuple, List[str]]:
        """
        Raggruppa i domini in base ai loro parametri di scansione.
        
        Returns:
            Dict con chiave (timing, max_rate) e valore lista di domini
        """
        groups = {}
        
        for domain in domains:
            params = target_params.get(domain, {})
            timing = params.get('timing', 'normal')
            max_rate = params.get('max_rate')
            
            key = (timing, max_rate)
            if key not in groups:
                groups[key] = []
            groups[key].append(domain)
        
        return groups
    
    def _build_args(self, scan_type: str, timing: str, max_rate: int = None) -> str:
        """
        Costruisce gli argomenti nmap basati su scan_type, timing e max_rate.
        """
        scan_type = scan_type.lower()
        if scan_type not in self.SCAN_PROFILES:
            scan_type = 'fast'
            
        args = self.SCAN_PROFILES[scan_type]
        
        # Aggiunge il parametro di timing se non esplicitamente definito nel profilo (es. noisy ha -T5)
        if "-T" not in args:
            if timing == 'polite':
                args += ' -T2'  # Polite timing
            else:
                args += ' -T4'  # Aggressive timing (normal)
        
        # Aggiunge il parametro di rate limiting se specificato
        if max_rate:
            args += f' --max-rate {max_rate}'
        
        return args
    
    def _scan_group(self, domains: List[str], args: str) -> None:
        """
        Scansiona un gruppo di domini con gli stessi argomenti.
        """

        for domain in domains:
            target_ip = None
            try:
                # Risoluzione DNS per ottenere l'IP del dominio prima della scansione
                target_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                print(f"ERRORE: Impossibile risolvere il dominio {domain}", file=sys.stderr)
                self.results[domain] = {"error": "Impossibile risolvere il nome a dominio (DNS Error)"}
                continue
            except Exception as e:
                self.results[domain] = {"error": f"Errore durante la risoluzione DNS: {str(e)}"}
                continue

            try:
                print(f"Avvio scansione su {domain} ({target_ip}) con argomenti: {args}", file=sys.stderr)
                
                # Esegue la scansione sull'IP risolto
                self.nm.scan(hosts=target_ip, arguments=args)
                
                # Memorizza i risultati
                scan_result = self.nm.all_hosts()
                if target_ip in scan_result:
                    self.results[domain] = self.nm[target_ip]
                else:
                    self.results[domain] = {"error": "Host scansionato ma nessun risultato restituito (potrebbe essere down o filtrare i pacchetti)"}
                    
            except Exception as e:
                self.results[domain] = {"error": str(e)}

    def get_results(self) -> str:
        """
        Returns:
            str: Una stringa JSON formattata con indentazione per leggibilità.
        """
        return json.dumps(self.results, indent=4)
