import os
import json
import shutil
import subprocess
import sys
import threading
import concurrent.futures
from typing import List, Dict, Any
from urllib.parse import urlparse
from .base_tool import Tool

class SpiderTool(Tool):
    """
    Esegue web crawling/spidering attivo usando Katana (ProjectDiscovery).
    Estrae endpoint generali per wordlist dinamiche e, in modo specifico, file JavaScript.
    """

    SCAN_PROFILES = {
        "fast": {"depth": 1, "rate": 50, "timeout": 5},
        "accurate": {"depth": 2, "rate": 100, "timeout": 10},
        "comprehensive": {"depth": 3, "rate": 0, "timeout": 15},
        "stealth": {"depth": 1, "rate": 5, "timeout": 10}
    }

    def __init__(self):
        super().__init__()
        self.results = {}
        self.lock = threading.Lock()
        
        self.katana_path = shutil.which("katana")
        if not self.katana_path:
            # Fallback path if bin is in regular user go/bin but not system PATH
            home_go_bin = os.path.expanduser("~/go/bin/katana")
            if os.path.exists(home_go_bin):
                self.katana_path = home_go_bin
            else:
                print("ATTENZIONE: Eseguibile 'katana' non trovato. Lo Spidering fallirà.", file=sys.stderr)

    def run(self, targets: List[str], params: Dict[str, Any], target_params: Dict[str, Dict] = None) -> None:
        """
        Esegue Katana sugli URL (live web targets).
        """
        if not self.katana_path:
            for t in targets:
                 self.results[t] = {"error": "katana non trovato nel PATH"}
            return
            
        if target_params is None:
             target_params = {}

        def _process_target(url: str):
            print(f"[{url}] Setup Spidering (Katana)...", file=sys.stderr)
            
            clean_url = url.replace('http://', '').replace('https://', '')
            base_domain = clean_url.split('/')[0].split(':')[0]
            
            scan_type = target_params.get(base_domain, {}).get("scan_type", params.get("scan_type", "fast")).lower()
            if scan_type not in self.SCAN_PROFILES:
                 scan_type = "fast"
                 
            profile = self.SCAN_PROFILES[scan_type]
            
            self._execute_katana(url, profile, scan_type, base_domain)

        # Katana is quite resource-heavy when running with headless/js-crawl, so keeping workers low
        max_workers = min(3, len(targets) if targets else 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_process_target, url) for url in targets]
            done, _ = concurrent.futures.wait(futures)
            for f in done:
                try:
                    f.result()
                except Exception as e:
                    print(f"Errore in un thread Spider: {e}", file=sys.stderr)

    def _execute_katana(self, url: str, profile: Dict[str, Any], scan_type: str, base_domain: str) -> None:
        cmd = [
            self.katana_path,
            "-u", url,
            "-silent", "-jsonl",
            "-aff", # Automatic Form Fill (Experimental)
            "-jc", # JS Crawling
            "-kf", "all", # Known Files (robots.txt, sitemap.xml)
            "-c", str(profile["rate"] if profile["rate"] > 0 else 50), # concurrency level
            "-d", str(profile["depth"]),
            "-ct", str(profile["timeout"] * 60) # Crawl Timeout (seconds). Katana will exit gracefully.
        ]
        
        # In stealth non riempiamo gli headers standard o non facciamo form fill
        if scan_type == "stealth":
             cmd.remove("-aff")
             cmd.remove("-kf")
             
        try:
             # Generoso timeout complessivo al processo, Katana ha timeout nativi sulle conn
             process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=(profile["timeout"] * 60) + 60)
             
             endpoints = set()
             js_files = set()
             
             if process.stdout:
                 for line in process.stdout.strip().split('\n'):
                     if not line.strip():
                         continue
                     try:
                         obj = json.loads(line)
                         request_url = obj.get("request", {}).get("endpoint", "")
                         if not request_url:
                             request_url = obj.get("endpoint", "")
                             
                         if request_url:
                             # Garantiamo che l'URL restituito da Katana sia associato al dominio di pertenenza
                             # Se l'URL inizia con / o è raw relative, lo ricolleghiamo alla root. 
                             # Altrimenti se ha già lo schema https:// ecc. verifichiamo che appartenga a noi (o terze parti come CDN)
                             
                             endpoints.add(request_url)
                             
                             # JS File Matcher (Strict Check per evitare falsi positivi come .json .map)
                             clean_q_url = request_url.split('?')[0].lower() # Rimuovi query parameters e lowercase
                             if clean_q_url.endswith('.js'):
                                 # Normalizziamo le URL javascript prima di esporle a Jsluice e ContentDiscovery
                                 # Katana spesso riporta il request_url già full e assoluto, ma a volte no.
                                 if request_url.startswith('//'):
                                     scheme = urlparse(url).scheme or 'http'
                                     normalized_js = f"{scheme}:{request_url}"
                                 elif request_url.startswith('/'):
                                     normalized_js = f"{url.rstrip('/')}{request_url}"
                                 elif request_url.startswith('http'):
                                     normalized_js = request_url
                                 else:
                                     normalized_js = f"{url.rstrip('/')}/{request_url}"
                                     
                                 js_files.add(normalized_js)
                     except json.JSONDecodeError:
                         pass
             
             # Estrai le paths assolute per usarle come wordlist (solo path, es. /api/users)
             paths_only = set()
             for ep in endpoints:
                 try:
                     parsed = urlparse(ep)
                     if parsed.path and parsed.path != "/":
                         path = parsed.path.rstrip('/') # Rimuovi trailing slash
                         if parsed.query:
                             # Keep query params but ensure no fragments # are inside
                             query = parsed.query.split('#')[0]
                             path = f"{path}?{query}"
                         if path:
                             paths_only.add(path)
                 except: continue
             
             with self.lock:
                 self.results[url] = {
                     "base_domain": base_domain, # Salviamo il dominio associato a questo URL scansito
                     "endpoints_count": len(endpoints),
                     "js_files_count": len(js_files),
                     "js_files": list(js_files),
                     "paths_wordlist": list(paths_only)
                 }
             print(f"[{url}] Spidering completato. {len(endpoints)} endpoint trovati ({len(js_files)} file JS).", file=sys.stderr)

        except subprocess.TimeoutExpired:
             print(f"[{url}] Timeout durante Spidering Katana.", file=sys.stderr)
             with self.lock:
                  self.results[url] = {"error": "Run Timeout"}
        except Exception as e:
             with self.lock:
                  self.results[url] = {"error": f"Katana crash: {str(e)}"}

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
