import os
import sys
import time
import urllib.request
from typing import List
from .base_tool import Tool

class DnsManagerTool(Tool):
    """
    Tool per la gestione centralizzata dei DNS resolvers pubblici.
    Scarica, valida (opzionale) e distribuisce una lista fresca di resolver
    per l'intera infrastruttura ASM.
    """

    RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    LOCAL_RESOLVERS_FILE = "wordlists/resolvers.txt"
    MAX_AGE_HOURS = 24
    FALLBACK_RESOLVERS = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9']

    def __init__(self):
        super().__init__()
        self.resolvers = []
        # Assicurati che la directory wordlists esista
        os.makedirs("wordlists", exist_ok=True)

    def run(self, params: dict = None) -> None:
        pass # Metodo inutilizzato in questo contesto, presente per conformità alla classe Tool

    def get_resolvers(self, max_count: int = 50) -> List[str]:
        """
        Restituisce una lista di DNS Resolvers. 
        Se il file locale è vecchio (più di 24 ore) o mancante, lo riscarica da Trickest.
        """
        if not self._is_local_file_fresh():
            self._download_resolvers()

        resolvers = self._load_local_resolvers()
        
        if not resolvers:
            print("  [!] Nessun resolver trovato nel file, utilizzo fallback.", file=sys.stderr)
            resolvers = self.FALLBACK_RESOLVERS

        # Ritorna i primi N resolver per non sovraccaricare il resolver python locale, 
        # oppure tutti se richiesto (passando 0 o None), ideale per massdns/puredns che gestiscono bene liste immense.
        if max_count and max_count > 0:
            return resolvers[:max_count]
        return resolvers

    def _is_local_file_fresh(self) -> bool:
        if not os.path.exists(self.LOCAL_RESOLVERS_FILE):
            return False
            
        file_mod_time = os.path.getmtime(self.LOCAL_RESOLVERS_FILE)
        current_time = time.time()
        age_hours = (current_time - file_mod_time) / 3600
        
        return age_hours < self.MAX_AGE_HOURS

    def _download_resolvers(self) -> None:
        print(f"  [*] Download resolvers pubblici aggiornati da {self.RESOLVERS_URL}...", file=sys.stderr)
        try:
            req = urllib.request.Request(self.RESOLVERS_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                
            # Filtra linee vuote o commenti
            valid_ips = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
            
            if valid_ips:
                with open(self.LOCAL_RESOLVERS_FILE, 'w') as f:
                    f.write('\n'.join(valid_ips))
                print(f"  [+] Salvati {len(valid_ips)} resolvers freschi in {self.LOCAL_RESOLVERS_FILE}", file=sys.stderr)
            else:
                print("  [!] Nessun resolver valido scaricato. Verrà utilizzato il file preesistente o il fallback.", file=sys.stderr)
                
        except Exception as e:
            print(f"  [!] Errore durante il download dei resolvers: {e}", file=sys.stderr)

    def _load_local_resolvers(self) -> List[str]:
        try:
            with open(self.LOCAL_RESOLVERS_FILE, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            return []

    def get_results(self) -> str:
        return '{"status": "ok"}'
