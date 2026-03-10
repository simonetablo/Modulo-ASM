import os
import json
import sys
from abc import ABC, abstractmethod
from typing import List, Dict, Any

# Root del progetto (cartella che contiene main.py, config/, tools/, ecc.)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Tool(ABC):
    """
    Classe base astratta per tutti i tool del modulo ASM.
    Tutti i tool specifici (es. NmapTool) devono ereditare da questa classe
    e implementare i metodi astratti `run` e `get_results`.
    """

    def __init__(self):
        """
        Inizializza il tool.
        Crea un dizionario vuoto `self.results` per memorizzare i risultati delle scansioni.
        """
        self.results = {}

    def load_config(self, tool_name: str, scan_type: str = None) -> Dict[str, Any]:
        """
        Carica la configurazione per il tool dal filesystem.
        
        Fallback chain:
          1. config/<tool_name>/<scan_type>_config.json  (profilo specifico)
          2. config/<tool_name>/config.json               (configurazione generica)
          3. {} (dizionario vuoto, nessun file trovato)
        
        Args:
            tool_name: Nome della cartella config del tool (es. "subdomain_enum").
            scan_type: Profilo di scansione (es. "fast", "accurate"). Può essere None.
            
        Returns:
            Dizionario con i parametri di configurazione.
        """
        config_dir = os.path.join(BASE_DIR, "config", tool_name)
        
        # 1. Prova il config specifico per profilo
        if scan_type:
            profile_path = os.path.join(config_dir, f"{scan_type}_config.json")
            if os.path.exists(profile_path):
                try:
                    with open(profile_path, 'r') as f:
                        config = json.load(f)
                    return config
                except (json.JSONDecodeError, IOError) as e:
                    print(f"WARNING: Errore lettura config {profile_path}: {e}", file=sys.stderr)
        
        # 2. Fallback al config generico
        generic_path = os.path.join(config_dir, "config.json")
        if os.path.exists(generic_path):
            try:
                with open(generic_path, 'r') as f:
                    config = json.load(f)
                return config
            except (json.JSONDecodeError, IOError) as e:
                print(f"WARNING: Errore lettura config {generic_path}: {e}", file=sys.stderr)
        
        # 3. Nessun file trovato
        print(f"WARNING: Nessun file di configurazione trovato per '{tool_name}' (scan_type={scan_type}). "
              f"Uso defaults hardcoded.", file=sys.stderr)
        return {}

    @staticmethod
    def merge_config(config: Dict[str, Any], params: Dict[str, Any], keys: List[str] = None) -> Dict[str, Any]:
        """
        Unisce la configurazione dal file con i parametri runtime (CLI/JSON).
        I parametri espliciti in `params` hanno la priorità sul config file.
        
        Args:
            config: Dizionario letto dal file config.
            params: Dizionario dei parametri runtime (CLI/JSON input).
            keys: Lista opzionale di chiavi da estrarre da params. Se None, merge tutte le chiavi.
            
        Returns:
            Dizionario risultante con priorità: params > config.
        """
        merged = dict(config)  # shallow copy del config
        
        if keys:
            # Merge solo le chiavi specificate
            for key in keys:
                if key in params and params[key] is not None:
                    merged[key] = params[key]
        else:
            # Merge completo: ogni chiave presente in params sovrascrive
            for key, value in params.items():
                if value is not None:
                    merged[key] = value
        
        return merged

    @abstractmethod
    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Esegue il tool sui domini specificati utilizzando i parametri forniti.
        Questo metodo deve essere implementato dalle sottoclassi.

        Args:
            domains (List[str]): Una lista di domini o indirizzi IP da scansionare.
            params (Dict[str, Any]): Un dizionario contenente i parametri di configurazione
            per la scansione (es. tipo di scansione, porte, timeout).
        """
        pass

    @abstractmethod
    def get_results(self) -> str:
        """
        Restituisce i risultati della scansione formattati come stringa JSON.
        Questo metodo deve essere implementato dalle sottoclassi.

        Returns:
            str: Una stringa contenente i risultati in formato JSON.
        """
        pass
