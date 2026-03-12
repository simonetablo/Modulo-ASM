import os
import json
import time
import requests
import sys
from typing import List, Dict, Any, Optional
from .base_tool import Tool, BASE_DIR

class WordlistManagerTool(Tool):
    """
    Gestisce Download e Update delle wordlist.
    Organizza le wordlist in categorie (subdomains, vhosts, content_discovery)
    e livelli di aggressività (fast, accurate, comprehensive).
    """

    DEFAULT_CONFIG = {
        "freshness_days": 30,
        "sources": {
            "subdomains": {
                "fast": "https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2026_02_27.txt",
                "accurate": "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
                "comprehensive": "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt"
            },
            "vhosts": {
                "default": "https://wordlists-cdn.assetnote.io/data/manual/virtual-host-scanning.txt"
            },
            "content_discovery": {
                "general": "https://wordlists-cdn.assetnote.io/data/manual/raft-medium-directories-lowercase.txt",
                "php": "https://wordlists-cdn.assetnote.io/data/manual/phpmillion.txt",
                "jsp": "https://wordlists-cdn.assetnote.io/data/manual/jsp.txt",
                "asp": "https://wordlists-cdn.assetnote.io/data/manual/asp_lowercase.txt",
                "js": "https://wordlists-cdn.assetnote.io/data/automated/httparchive_js_2026_02_27.txt",
                "apiroutes": "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2026_02_27.txt",
                "cgi": "https://wordlists-cdn.assetnote.io/data/automated/httparchive_cgi_pl_2026_02_27.txt",
                "html": "https://wordlists-cdn.assetnote.io/data/automated/httparchive_html_htm_2026_02_27.txt"
            },
            "dns": {
                "resolvers": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
                "trusted": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"
            },
            "permutations": {
                "default": "https://wordlists-cdn.assetnote.io/data/manual/raft-small-words-lowercase.txt"
            }
        }
    }

    WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists/wlmanager")

    # Mappatura interna per risolvere tecnologie a wordlist specifiche
    TECH_MAPPING = {
        "wordpress": "php",
        "iis": "asp",
        "asp.net": "asp",
        "tomcat": "jsp",
        "spring": "jsp",
        "node.js": "apiroutes",
        "python": "apiroutes",
        "django": "apiroutes",
        "ruby": "apiroutes",
        "express": "apiroutes",
        "apache": "html",
        "nginx": "html"
    }

    def __init__(self):
        super().__init__()
        os.makedirs(self.WORDLISTS_DIR, exist_ok=True)
        # Carica configurazione da file
        file_config = self.load_config("wordlist_manager")
        self._config = {**self.DEFAULT_CONFIG, **file_config}

    def run(self, domains: List[str] = None, params: Dict[str, Any] = None) -> None:
        """
        In questo contesto viene usato per sincronizzare tutte le wordlist.
        """
        force_update = params.get("update_wordlists", False) if params else False
        self.update_all(force=force_update)

    def update_all(self, force: bool = False) -> None:
        """
        Controlla tutte le wordlist configurate e le scarica se mancanti o vecchie.
        """
        print(f"[*] Sincronizzazione wordlist (force={force})...", file=sys.stderr)
        sources = self._config.get("sources", {})
        for category, configs in sources.items():
            if isinstance(configs, dict):
                for level, url in configs.items():
                    self._ensure_wordlist(category, level, url, force)
            else:
                self._ensure_wordlist(category, "default", configs, force)

    def get_wordlist(self, category: str, level: str = "fast", tech: Optional[str] = None) -> str:
        """
        Restituisce il path assoluto della wordlist richiesta.
        Se la wordlist non è presente o è vecchia, prova a scaricarla.
        """
        sources = self._config.get("sources", {})
        cat_config = sources.get(category, {})
        
        # Gestione speciale per content_discovery basato su tecnologia
        if category == "content_discovery" and tech:
            tech_key = self.TECH_MAPPING.get(tech.lower(), tech.lower())
            url = cat_config.get(tech_key)
            if url:
                level = tech_key
            else:
                url = cat_config.get("general")
                level = "general"
        else:
            # Fallback chain per i livelli: accurate -> fast, comprehensive -> accurate -> fast
            url = cat_config.get(level)
            if not url and level == "comprehensive":
                url = cat_config.get("accurate") or cat_config.get("fast")
                if url: level = "accurate" if cat_config.get("accurate") else "fast"
            if not url and level == "accurate":
                url = cat_config.get("fast")
                if url: level = "fast"
            if not url:
                if cat_config.get("default"):
                    url = cat_config.get("default")
                    level = "default"
                else:
                    url = cat_config.get("fast")
                    level = "fast"

        if not url:
            # Fallback definitivo alla wordlist legacy se possibile
            legacy_map = {
                "subdomains": "wordlists/subdomains.txt",
                "vhosts": "wordlists/vhosts.txt",
                "content_discovery": "wordlists/content_discovery.txt"
            }
            return os.path.join(BASE_DIR, legacy_map.get(category, f"wordlists/{category}.txt"))

        # Assicura che il file sia presente
        filepath = self._ensure_wordlist(category, level, url)
        return filepath

    def _ensure_wordlist(self, category: str, level: str, url: str, force: bool = False) -> str:
        filename = f"{category}_{level}.txt"
        filepath = os.path.join(self.WORDLISTS_DIR, filename)

        if force or not self._is_fresh(filepath):
            self._download(url, filepath)
        
        return filepath

    def _is_fresh(self, filepath: str) -> bool:
        if not os.path.exists(filepath):
            return False
            
        # Controlla la dimensione (non deve essere un file di errore 404 o simile)
        if os.path.getsize(filepath) < 100:
            return False

        freshness_days = self._config.get("freshness_days", 30)
        file_mod_time = os.path.getmtime(filepath)
        current_time = time.time()
        age_days = (current_time - file_mod_time) / (24 * 3600)
        
        return age_days < freshness_days

    def _download(self, url: str, dest: str) -> bool:
        print(f"  [+] Download wordlist: {url} -> {os.path.basename(dest)}", file=sys.stderr)
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Scrittura chunked per gestire file grandi
            with open(dest, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return True
        except Exception as e:
            print(f"  [!] Errore durante il download di {url}: {e}", file=sys.stderr)
            return False

    def get_results(self) -> str:
        return json.dumps({"status": "ready", "path": self.WORDLISTS_DIR}, indent=4)
