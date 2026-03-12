import json
import sys
import subprocess
import shutil
import os
import tempfile
import re
from collections import defaultdict
from typing import List, Dict, Any
from .base_tool import Tool

class PermutationTool(Tool):
    """
    Tool per la generazione di permutazioni di sottodomini utilizzando 'alterx'.
    Parametri caricati da config/permutation/<scan_type>_config.json.
    """

    # Defaults hardcoded come ultimo fallback se nessun file config è presente
    DEFAULT_CONFIG = {
        "max_wildcards": 5,
        "min_occurrences": 3,
        "process_timeout": 900
    }

    def __init__(self):
        """
        Inizializza il tool e verifica le dipendenze.
        """
        super().__init__()
        self.alterx_path = shutil.which("alterx")
        if not self.alterx_path:
            home_go_bin = os.path.expanduser("~/go/bin/alterx")
            if os.path.exists(home_go_bin):
                self.alterx_path = home_go_bin
            else:
                self.alterx_path = None
                print("ATTENZIONE: Eseguibile 'alterx' non trovato. La generazione di permutazioni fallirà.", file=sys.stderr)

    def run(self, domains: List[str], params: Dict[str, Any], wl_manager: Any = None) -> None:
        """
        Genera permutazioni per la lista di domini fornita.
        
        Args:
            domains: Lista di domini "seed" da cui generare permutazioni.
            params: Parametri opzionali per alterx (es. patterns custom).
        """
        if not self.alterx_path:
             for target in domains:
                self.results[target] = {"error": "Dipendenza 'alterx' non trovata"}
             return

        self.results = {}

        input_file_path = None
        patterns_file_path = None
        payload_file_path = None
        common_payload_path = None

        try:
            # -------------------------------------------------------------------
            # MOTORE EURISTICO: Estrazione Pattern e Costruzione Payload AlterX
            # -------------------------------------------------------------------
            scan_type = params.get("scan_type", "fast").lower()
            
            # Carica configurazione da file con fallback chain
            file_config = self.load_config("permutation", scan_type)
            config = {**self.DEFAULT_CONFIG, **file_config}
            # I parametri espliciti da CLI/JSON hanno priorità
            config = self.merge_config(config, params, ["max_wildcards", "min_occurrences", "process_timeout"])
            
            max_wildcards = config.get("max_wildcards", 5)
            min_occurrences = config.get("min_occurrences", 3)
            extracted_patterns = self._extract_patterns(domains, scan_type=scan_type, min_occurrences=min_occurrences, max_wildcards=max_wildcards)
            local_payload = self._generate_payload(domains)
            
            # Scrive input, pattern e payload su file temporanei
            input_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='_input.txt')
            input_file.write('\n'.join(domains))
            input_file_path = input_file.name
            input_file.close()
            
            # Se abbiamo trovato strutture logiche valide
            if extracted_patterns:
                patterns_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='_patterns.txt')
                # Aggiungiamo i pattern custom generati
                patterns_file.write('\n'.join(extracted_patterns))
                patterns_file_path = patterns_file.name
                patterns_file.close()
                
                payload_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='_payload.txt')
                payload_file.write('\n'.join(local_payload))
                payload_file_path = payload_file.name
                payload_file.close()
                
                # Crea e valorizza la wordlist "Common/Generica"
                custom_common_path = params.get("permutations_wordlist")
                if custom_common_path and os.path.exists(custom_common_path):
                    common_payload_path = custom_common_path
                    print(f"  [*] Uso wordlist 'common' personalizzata: {custom_common_path}", file=sys.stderr)
                elif wl_manager:
                    common_payload_path = wl_manager.get_wordlist("permutations")
                    print(f"  [*] Uso wordlist 'common' centralizzata: {common_payload_path}", file=sys.stderr)
                else:
                    # Fallback estremo se non c'è il manager (es. test unitari isolati)
                    common_words = ["api", "dev", "test", "prod", "admin", "mail", "vpn"]
                    common_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='_common.txt')
                    common_file.write('\n'.join(common_words))
                    common_payload_path = common_file.name
                    common_file.close()

            cmd = [
                self.alterx_path,
                "-l", input_file_path,
                "-silent"
            ]
            
            # Utilizza il Motore Smart di Pattern solo se sono stati trovati
            if patterns_file_path and payload_file_path and common_payload_path:
                print(f"Istruisco AlterX con {len(extracted_patterns)} pattern euristici e un vocabolario di {len(local_payload)} parole estratte dai target.", file=sys.stderr)
                cmd.extend(["-pattern", patterns_file_path])
                # Double Payload Feature (Locale + Universale)
                cmd.extend(["-payload", f"word={payload_file_path}"])
                cmd.extend(["-payload", f"common={common_payload_path}"])
            else:
                print(f"Nessun pattern strutturale rilevante trovato. AlterX userà l'algoritmo di default combinatorio.", file=sys.stderr)
            
            if "flags" in params:
                cmd.extend(params["flags"])

            print(f"Esecuzione alterx su {len(domains)} subdomains seed...", file=sys.stderr)
            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=config.get("process_timeout", 900)
                )
            except subprocess.TimeoutExpired:
                print(f"Errore: alterx ha superato il timeout.", file=sys.stderr)
                return

            if process.returncode != 0:
                print(f"Errore alterx: {process.stderr}", file=sys.stderr)
            
            permutations = list(set(line.strip() for line in process.stdout.splitlines() if line.strip()))
            
            for target in domains:
                target_permutations = [p for p in permutations if p.endswith(target)]
                # Poiché il target è spesso se stesso (il root), restituiamo 
                # a 'target' le permutazioni figlie che contengono il target come suffisso finale
                self.results[target] = {
                    "permutations": target_permutations,
                    "count": len(target_permutations)
                }

        except Exception as e:
            print(f"Eccezione durante esecuzione alterx: {str(e)}", file=sys.stderr)
            for target in domains:
                self.results[target] = {"error": str(e)}
        finally:
            if input_file_path and os.path.exists(input_file_path):
                os.remove(input_file_path)
            if patterns_file_path and os.path.exists(patterns_file_path):
                os.remove(patterns_file_path)
            if payload_file_path and os.path.exists(payload_file_path):
                os.remove(payload_file_path)
            custom_common_path = params.get("permutations_wordlist")
            if common_payload_path and common_payload_path != custom_common_path and os.path.exists(common_payload_path):
                os.remove(common_payload_path)

    def _extract_patterns(self, domains: List[str], scan_type: str = "fast", min_occurrences: int = 3, max_wildcards: int = 5) -> List[str]:
        """
        Motore Euristico Avanzato (Advanced Pattern Extractor):
        Analizza i domini in ingresso tramutando l'intera logica 
        su N livelli di profondità per restituire template AlterX purissimi.
        Include Apprendimento Costanti dinamico dipendente dallo scan_type
        e Constant Anchoring basato sul budget di variabili ammesse (max_wildcards).
        """
        patterns = set()
        is_fast_stealth = scan_type in ["fast", "stealth"]
        
        # In Comprehensive/Accurate inseriamo da subito i fall-back globali enormi
        if not is_fast_stealth:
            patterns.add('{{word}}.{{domain}}')
            patterns.add('{{common}}.{{domain}}')
            patterns.add('{{domain}}-{{word}}')
            patterns.add('{{domain}}-{{common}}')
            
        # --- PASS 1: Analisi Frequenze per Constant Learning (solo Fast/Stealth) ---
        constant_freqs = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        
        if is_fast_stealth:
            for dom in domains:
                parts = dom.split('.')
                if len(parts) >= 3:
                    for sub_part in parts[:-2]:
                        dash_tokens = sub_part.split('-')
                        n_tokens = len(dash_tokens)
                        for i, token in enumerate(dash_tokens):
                            if not token.isdigit():
                                constant_freqs[n_tokens][i][token.lower()] += 1

        # --- PASS 2: Generazione Pattern e Rolling Depth Cascade ---
        for dom in domains:
            parts = dom.split('.')
            if len(parts) < 3:
                continue # Evitiamo i raw domains
                
            sub_levels = parts[:-2]
            n_levels = len(sub_levels)
            
            # 1. Copertura Assoluta a Cascata (Pure Wildcards per n-livelli decrescenti)
            # Indipendentemente dal profilo, assicuriamo le root da 1 a N
            for i in range(1, n_levels + 1):
                # Es. Per i=2 genera: {{word}}.{{word}}.{{domain}}
                pure_pattern = ".".join(["{{word}}"] * i) + ".{{domain}}"
                patterns.add(pure_pattern)
                
            # Produciamo la cascata decrescente anche per le architetture Semantiche (Es. app.api.v1 -> api.v1 -> v1)
            for cascade_offset in range(n_levels):
                # Ad ogni giro accorcia da sinistra (tronca il nodo più alto)
                current_levels = sub_levels[cascade_offset:]
                level_templates = []
                has_constants_in_dom = False
                
                for sub_part in current_levels:
                    dash_tokens = sub_part.split('-')
                    n_tokens = len(dash_tokens)
                    parsed_dash_tokens = []
                    
                    for i, token in enumerate(dash_tokens):
                        is_constant = False
                        token_lower = token.lower()
                        
                        if is_fast_stealth and not token.isdigit():
                            if constant_freqs[n_tokens][i][token_lower] >= min_occurrences:
                                is_constant = True
                                
                        if is_constant:
                            parsed_dash_tokens.append(token_lower)
                            has_constants_in_dom = True
                        else:
                            match = re.match(r'^([a-zA-Z]+)(\d+)$', token)
                            if match:
                                parsed_dash_tokens.append('{{word}}{{number}}')
                            elif token.isdigit():
                                parsed_dash_tokens.append('{{number}}')
                            else:
                                parsed_dash_tokens.append('{{word}}')
                            
                    level_templates.append("-".join(parsed_dash_tokens))
                    
                # SMART CONSTANT ANCHORING (Salvamissione Over-Wildcards)
                total_wildcards = sum(tpl.count('{{word}}') for tpl in level_templates)
                
                if total_wildcards > max_wildcards:
                    wildcards_to_anchor = total_wildcards - max_wildcards
                    anchored_count = 0
                    
                    for level_index, tpl in enumerate(level_templates):
                        if anchored_count >= wildcards_to_anchor:
                            break
                            
                        tokens_in_level = tpl.split('-')
                        original_tokens = current_levels[level_index].split('-')
                        
                        for t_index, t_val in enumerate(tokens_in_level):
                            if '{{word}}' in t_val and anchored_count < wildcards_to_anchor:
                                t_val = t_val.replace('{{word}}', original_tokens[t_index].lower())
                                tokens_in_level[t_index] = t_val
                                anchored_count += 1
                                
                        level_templates[level_index] = "-".join(tokens_in_level)
                        
                smart_pattern_local = ".".join(level_templates) + ".{{domain}}"
                
                if is_fast_stealth:
                    if has_constants_in_dom:
                        patterns.add(smart_pattern_local)
                        if '{{word}}' in smart_pattern_local:
                            cross_pattern = smart_pattern_local.replace('{{word}}', '{{common}}', 1)
                            patterns.add(cross_pattern)
                else:
                    patterns.add(smart_pattern_local)
                    if '{{word}}' in smart_pattern_local:
                        cross_pattern = smart_pattern_local.replace('{{word}}', '{{common}}', 1)
                        patterns.add(cross_pattern)

        if is_fast_stealth and not patterns:
            patterns.add('{{word}}.{{domain}}')
            patterns.add('{{common}}.{{domain}}')

        return list(patterns)
        
    def _generate_payload(self, domains: List[str]) -> List[str]:
        """
        Estrae le parole isolate presenti nei sottodomini filtrando hash inservibili 
        per formare un vocabolario locare compatto e di altissimo valore ({{word}}).
        """
        words = set()
        for dom in domains:
            # Dividiamo basandoci su punti e trattini
            tokens = re.split(r'[.-]', dom)
            for token in tokens:
                if len(token) > 1 and not token.isdigit():
                    # Stop-Words Filtraggio Hash (Scartiamo lunghi hash alfanumerici casuali es. b6f2a8c3)
                    # Migliorato: scarta stringhe hex >= 8 caratteri anche se puramente alfabetiche (es. ffffffff) o miste
                    if len(token) >= 8 and re.match(r'^[a-fA-F0-9]+$', token):
                        continue 
                    words.add(token.lower())
                    
        return list(words)

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
