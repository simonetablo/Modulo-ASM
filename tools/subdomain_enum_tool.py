import json
import sys
import subprocess
import shutil
import os
from typing import List, Dict, Any
from .base_tool import Tool

class SubdomainEnumTool(Tool):
    """
    Tool per la subdomain enumeration attiva.
    Utilizza 'puredns' per il bruteforce dei sottodomini.
    """

    SCAN_PROFILES = {
        "fast": {
            "wordlist": "wordlists/test_subs.txt",
            "flags": ["-l", "1000"]
        },
        "comprehensive": {
            "wordlist": "wordlists/test_subs.txt",
            "flags": ["-l", "5000"]
        },
        "stealth": {
            "wordlist": "wordlists/test_subs.txt",
            "flags": ["-l", "100"]
        },
        "noisy": {
            "wordlist": "wordlists/test_subs.txt",
            "flags": ["-l", "10000"]
        }
    }

    def __init__(self, dns_resolvers: List[str] = None):
        """
        Inizializza il tool con DNS resolvers e verifica le dipendenze.
        
        Args:
            dns_resolvers: Lista di DNS resolver IPs.
        """
        super().__init__()
        self.dns_resolvers = dns_resolvers or ['1.1.1.1', '8.8.8.8']
        self.results = {}
        
        # Verifica dipendenze
        self.puredns_path = shutil.which("puredns")
        self.massdns_path = shutil.which("massdns")
        
        if not self.puredns_path:
            print("ATTENZIONE: Eseguibile 'puredns' non trovato nel PATH.", file=sys.stderr)
        if not self.massdns_path:
            print("ATTENZIONE: Eseguibile 'massdns' non trovato nel PATH. Puredns fallirà il bruteforce.", file=sys.stderr)

    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Esegue l'enumerazione dei sottodomini.
        Modalità supportate:
        - "bruteforce" (default): Usa wordlist per trovare sottodomini.
        - "resolve": Valida una lista di domini candidati (in 'domains').
        """
        method = params.get("method", "bruteforce").lower()
        
        if not self.puredns_path or not self.massdns_path:
            for target in domains:
                self.results[target] = {"error": "Dipendenze (puredns/massdns) non trovate"}
            return

        # Crea un file temporaneo per i risolutori
        resolvers_file = "temp_resolvers.txt"
        with open(resolvers_file, "w") as f:
            f.write("\n".join(self.dns_resolvers))

        try:
            if method == "resolve":
                # In modalità resolve, 'domains' contiene i candidati da validare (es. output di alterx)
                # Puredns resolve accetta un file con i domini da risolvere
                candidates_file = "temp_candidates.txt"
                with open(candidates_file, "w") as f:
                    f.write("\n".join(domains))
                
                print(f"Avvio validazione DNS per {len(domains)} candidati...", file=sys.stderr)
                resolved = self._run_puredns_resolve(candidates_file, resolvers_file)
                
                # Salviamo i risultati. Puredns resolve restituisce quelli validi.
                # In questo caso non c'è un "target" padre chiaro se la lista è mista,
                # ma se stiamo validando permutazioni di X, potremmo volerli raggruppare.
                # Per semplicità, e coerenza, restituiamo i domini validati in una struttura
                # che il chiamante possa usare.
                # Se il chiamante ha passato [sub1.test.com, sub2.test.com],
                # noi restituiamo quali di questi sono attivi.
                
                self.results["resolved_domains"] = {
                    "count": len(resolved),
                    "domains": resolved
                }
                
                if os.path.exists(candidates_file):
                    os.remove(candidates_file)

            else: # Default: bruteforce
                scan_type = params.get("scan_type", "fast").lower()
                wordlist_path, additional_flags = self._build_args(scan_type, params)

                if not os.path.exists(wordlist_path):
                    print(f"Errore: Wordlist non trovata in {wordlist_path}", file=sys.stderr)
                    for target in domains:
                        self.results[target] = {"error": f"Wordlist non trovata: {wordlist_path}"}
                    return

                for target in domains:
                    print(f"Avvio subdomain enumeration attiva ({scan_type}) su {target}...", file=sys.stderr)
                    discovered = self._run_puredns_bruteforce(target, wordlist_path, resolvers_file, additional_flags)
                    self.results[target] = {
                        "discovered_subdomains": discovered,
                        "count": len(discovered)
                    }

        finally:
            # Pulizia
            if os.path.exists(resolvers_file):
                os.remove(resolvers_file)

    def _build_args(self, scan_type: str, params: Dict[str, Any]) -> tuple:
        """
        Costruisce gli argomenti per puredns bruteforce in base al profilo di scansione.
        """
        if scan_type not in self.SCAN_PROFILES:
            print(f"ATTENZIONE: scan_type '{scan_type}' non riconosciuto. Utilizzo 'fast'.", file=sys.stderr)
            scan_type = "fast"
        
        profile = self.SCAN_PROFILES[scan_type]
        wordlist_path = params.get("wordlist") or profile["wordlist"]
        additional_flags = profile.get("flags", [])
        
        return wordlist_path, additional_flags

    def _run_puredns_bruteforce(self, domain: str, wordlist: str, resolvers: str, flags: List[str] = None) -> List[str]:
        """
        Esegue puredns bruteforce.
        """
        cmd = [
            self.puredns_path,
            "bruteforce",
            wordlist,
            domain,
            "-r", resolvers,
            "--quiet"
        ]
        if flags:
            cmd.extend(flags)
        
        return self._execute_puredns(cmd)

    def _run_puredns_resolve(self, candidates_file: str, resolvers: str) -> List[str]:
        """
        Esegue puredns resolve su una lista di candidati.
        """
        cmd = [
            self.puredns_path,
            "resolve",
            candidates_file,
            "-r", resolvers,
            "--quiet"
        ]
        return self._execute_puredns(cmd)

    def _execute_puredns(self, cmd: List[str]) -> List[str]:
        """
        Helper per eseguire il comando puredns e parsare l'output.
        """
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            # Filtra le linee vuote e restituisce i domini unici
            results = list(set(line.strip() for line in process.stdout.splitlines() if line.strip()))
            return results
        except Exception as e:
            print(f"Eccezione durante esecuzione puredns: {str(e)}", file=sys.stderr)
            return []

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
