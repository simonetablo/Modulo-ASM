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
        Esegue il brute-force dei sottodomini per i domini forniti.
        """
        if not self.puredns_path or not self.massdns_path:
            for target in domains:
                self.results[target] = {"error": "Dipendenze (puredns/massdns) non trovate"}
            return

        wordlist_path = params.get("wordlist", "wordlists/test_subs.txt")
        if not os.path.exists(wordlist_path):
            print(f"Errore: Wordlist non trovata in {wordlist_path}", file=sys.stderr)
            for target in domains:
                self.results[target] = {"error": f"Wordlist non trovata: {wordlist_path}"}
            return

        # Crea un file temporaneo per i risolutori se necessario (puredns lo richiede spesso)
        resolvers_file = "temp_resolvers.txt"
        with open(resolvers_file, "w") as f:
            f.write("\n".join(self.dns_resolvers))

        for target in domains:
            print(f"Avvio subdomain enumeration attiva su {target}...", file=sys.stderr)
            discovered = self._run_puredns(target, wordlist_path, resolvers_file)
            self.results[target] = {
                "discovered_subdomains": discovered,
                "count": len(discovered)
            }

        # Pulizia
        if os.path.exists(resolvers_file):
            os.remove(resolvers_file)

    def _run_puredns(self, domain: str, wordlist: str, resolvers: str) -> List[str]:
        """
        Esegue puredns bruteforce e restituisce la lista dei sottodomini trovati.
        """
        cmd = [
            self.puredns_path,
            "bruteforce",
            wordlist,
            domain,
            "-r", resolvers,
            "--quiet"
        ]
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Filtra le linee vuote e restituisce i domini unici
            subdomains = list(set(line.strip() for line in process.stdout.splitlines() if line.strip()))
            return subdomains
            
        except Exception as e:
            print(f"Eccezione durante esecuzione puredns su {domain}: {str(e)}", file=sys.stderr)
            return []

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
