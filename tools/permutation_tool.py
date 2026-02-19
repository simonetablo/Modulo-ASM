import json
import sys
import subprocess
import shutil
import os
import tempfile
from typing import List, Dict, Any
from .base_tool import Tool

class PermutationTool(Tool):
    """
    Tool per la generazione di permutazioni di sottodomini utilizzando 'alterx'.
    """

    def __init__(self):
        """
        Inizializza il tool e verifica le dipendenze.
        """
        super().__init__()
        self.alterx_path = shutil.which("alterx") or "/home/simone/go/bin/alterx"
        
        if not os.path.exists(self.alterx_path) and not shutil.which("alterx"):
             print(f"ATTENZIONE: Eseguibile 'alterx' non trovato in {self.alterx_path} né nel PATH.", file=sys.stderr)

    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
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

        # Pulisce i risultati precedenti
        self.results = {}

        # Crea un file temporaneo con i domini di input
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as input_file:
            input_file.write('\n'.join(domains))
            input_file_path = input_file.name

        try:
            # Esegui alterx
            cmd = [
                self.alterx_path,
                "-l", input_file_path,
                "-silent"
            ]
            
            # Aggiungi eventuali flag extra dai parametri
            if "flags" in params:
                cmd.extend(params["flags"])

            print(f"Esecuzione alterx su {len(domains)} subdomains di {domains[0]}...", file=sys.stderr)
            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30  # Timeout di 30 secondi per evitare blocchi
                )
            except subprocess.TimeoutExpired:
                print(f"Errore: alterx ha superato il timeout di 30s.", file=sys.stderr)
                # In caso di timeout, potremmo voler uccidere il processo se non lo fa subprocess.run
                return

            if process.returncode != 0:
                print(f"Errore alterx: {process.stderr}", file=sys.stderr)
                # In caso di errore, restituisci comunque eventuali risultati parziali se presenti
            
            permutations = list(set(line.strip() for line in process.stdout.splitlines() if line.strip()))
            
            # Alterx non raggruppa per dominio seed, quindi restituiamo un risultato "globale"
            # O possiamo associarlo al primo dominio se ha senso, ma qui è meglio un risultato aggregato.
            # Tuttavia, la struttura `Tool` si aspetta results[domain]. 
            # Per ora salviamo tutto sotto una chiave speciale o duplichiamo per ogni seed (inefficiente).
            # Meglio: Salviamo i risultati grezzi in una chiave generica "_permutations" o simile,
            # ma per rispettare l'interfaccia base, possiamo associare i risultati a ciascun dominio di input 
            # filtrando quelli che contengono il dominio (se alterx mantiene il suffisso).
            
            # Dato che alterx mescola tutto, salviamo l'intera lista sotto una chiave fittizia o associata al primo dominio
            # Oppure cambiamo l'approccio: restituiamo l'intera lista nel campo 'permutations' di ogni target
            # (ridondante ma sicuro).
            
            # Approccio migliore: Salviamo tutto in self.results['_global'] se il caller lo supporta,
            # ma per compatibilità con il loop in main.py, potremmo doverlo gestire diversamente.
            # Per ora, restituiamo un campo "permutations" per ogni dominio di input che contiene
            # le permutazioni *relative* a quel dominio.
            
            for target in domains:
                # Filtra le permutazioni che finiscono con il dominio target
                target_permutations = [p for p in permutations if p.endswith(target)]
                self.results[target] = {
                    "permutations": target_permutations,
                    "count": len(target_permutations)
                }

        except Exception as e:
            print(f"Eccezione durante esecuzione alterx: {str(e)}", file=sys.stderr)
            for target in domains:
                self.results[target] = {"error": str(e)}
        finally:
            if os.path.exists(input_file_path):
                os.remove(input_file_path)

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
