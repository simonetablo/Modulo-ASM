import json
import sys
import subprocess
import shutil
import os
import string
import random
import tempfile
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
        "accurate": {
            "wordlist": "wordlists/test_subs.txt",
            "flags": ["-l", "5000"]
        },
        "comprehensive": {
            "wordlist": "wordlists/test_subs.txt",
            "flags": ["-l", "500"] 
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

    SMART_AFFIXES = [
        "-dev", "-prod", "-staging", "-test", "-uat", "-api", "-v1", "-v2",
        "api-", "dev-", "test-", "staging-", "new-", "old-"
    ]

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

        # Crea un file temporaneo per i risolutori con un nome file universale unico
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='_resolvers.txt') as f:
            f.write("\n".join(self.dns_resolvers))
            resolvers_file = f.name

        try:
            if method == "resolve":
                # In modalità resolve, 'domains' contiene i candidati da validare (es. output di alterx)
                # Puredns resolve accetta un file con i domini da risolvere
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='_candidates.txt') as f:
                    f.write("\n".join(domains))
                    candidates_file = f.name
                
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
                smart_mode = params.get("smart", True)
                max_depth = params.get("max_depth", 5)
                wordlist_path, additional_flags = self._build_args(scan_type, params)

                if not os.path.exists(wordlist_path):
                    print(f"Errore: Wordlist non trovata in {wordlist_path}", file=sys.stderr)
                    for target in domains:
                        self.results[target] = {"error": f"Wordlist non trovata: {wordlist_path}"}
                    return

                for target in domains:
                    print(f"Avvio subdomain enumeration attiva ({scan_type}) su {target} [max_depth={max_depth}]...", file=sys.stderr)
                    
                    all_discovered = set()
                    scanned_bases = set()
                    
                    # Coda per il bruteforce ricorsivo: inseriamo solo il dominio
                    queue = [target]
                    
                    while queue:
                        current_target = queue.pop(0)
                        
                        if current_target in scanned_bases:
                            continue
                            
                        scanned_bases.add(current_target)
                        
                        # Calcolo la profondità effettiva del target corrente rispetto al root
                        # Esempio: target = example.com, current = api.example.com -> depth = 1 (1 label in più)
                        current_depth = len(current_target.split('.')) - len(target.split('.'))
                        
                        if current_depth > 0:
                            print(f"  -> Livello Sottodominio {current_depth}/{max_depth}: bruteforce ricorsivo su {current_target}...", file=sys.stderr)
                            
                        # Wildcard Check (Early-Exit): lo eseguiamo solo nei profili 'fast' o 'stealth'
                        # per risparmiare query inutili sui resolver sui rami catch-all.
                        # Per 'comprehensive' o 'noisy', lasciamo fare l'intero lavoro all'algoritmo
                        # interno di puredns, che è più preciso ma più lento/dispendioso.
                        skip_bruteforce = False
                        if scan_type in ["fast", "stealth"]:
                            random_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
                            wildcard_check_domain = f"{random_prefix}.{current_target}"
                            
                            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='_wildcard.txt') as f:
                                f.write(wildcard_check_domain)
                                wildcard_path = f.name
                            wildcard_result = self._run_puredns_resolve(wildcard_path, resolvers_file)
                            if os.path.exists(wildcard_path):
                                os.remove(wildcard_path)

                            if wildcard_result:
                                print(f"  [!] Rilevato Wildcard su {current_target}. Salto il bruteforce per questo ramo ({scan_type} mode).", file=sys.stderr)
                                skip_bruteforce = True
                                
                        if skip_bruteforce:
                            continue
                            
                        discovered = self._run_puredns_bruteforce(current_target, wordlist_path, resolvers_file, additional_flags)
                        
                        new_subdomains = set(discovered) - all_discovered
                        
                        # --- INIZIO SMART PERMUTATIONS ON-THE-FLY ---
                        if smart_mode and new_subdomains:
                            smart_resolved = self._run_smart_permutations(current_target, new_subdomains, all_discovered, resolvers_file)
                            if smart_resolved:
                                new_subdomains.update(smart_resolved)
                        # --- FINE SMART PERMUTATIONS ON-THE-FLY ---

                        all_discovered.update(new_subdomains)
                        
                        # Accodiamo i nuovi sottodomini scoperti solo se la loro profondità assoluta non eccede max_depth
                        for sub in new_subdomains:
                            if sub.endswith(f".{current_target}") and sub != current_target:
                                # Calcolo la profondità del NUOVO sottodominio rispetto alla root iniziale
                                sub_depth = len(sub.split('.')) - len(target.split('.'))
                                if sub_depth < max_depth:
                                    # Se sub_depth è minore della profondità massima consentita come BASE, lo accodiamo
                                    queue.append(sub)
                                    
                    self.results[target] = {
                        "discovered_subdomains": sorted(list(all_discovered)),
                        "count": len(all_discovered)
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

    def _run_smart_permutations(self, current_target: str, new_subdomains: set, all_discovered: set, resolvers_file: str) -> set:
        """
        Genera e risolve micro-permutazioni on-the-fly basate sui risultati correnti.
        """
        smart_candidates = set()
        for sub in new_subdomains:
            if sub.endswith(f".{current_target}") and sub != current_target:
                prefix = sub[:-(len(current_target)+1)]
                for affix in self.SMART_AFFIXES:
                    if affix.startswith("-"):
                        smart_candidates.add(f"{prefix}{affix}.{current_target}")
                    elif affix.endswith("-"):
                        smart_candidates.add(f"{affix}{prefix}.{current_target}")
        
        smart_candidates = smart_candidates - all_discovered - new_subdomains
        
        if not smart_candidates:
            return set()
            
        print(f"  [+] Generazione Smart: '{len(smart_candidates)}' micro-permutazioni dal target {current_target}...", file=sys.stderr)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='_smart.txt') as f:
            f.write("\n".join(smart_candidates))
            candidates_file = f.name
        
        smart_resolved = self._run_puredns_resolve(candidates_file, resolvers_file)
        
        if os.path.exists(candidates_file):
            os.remove(candidates_file)
            
        if smart_resolved:
            print(f"  [+] Scoperte '{len(smart_resolved)}' nuove permutazioni on-the-fly!", file=sys.stderr)
            
        return set(smart_resolved)

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
