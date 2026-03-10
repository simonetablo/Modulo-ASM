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
import re

class SpiderTool(Tool):
    """
    Esegue web crawling/spidering attivo usando Katana (ProjectDiscovery).
    Estrae endpoint generali per wordlist dinamiche e, in modo specifico, file JavaScript.
    Parametri caricati da config/spider/<scan_type>_config.json.
    """

    # Defaults hardcoded come ultimo fallback se nessun file config è presente
    DEFAULT_CONFIG = {
        "depth": 1,
        "rate": 300,
        "timeout_minutes": 5,
        "max_workers": 3,
        "auto_form_fill": True,
        "known_files": True,
        "js_crawling": True
    }

    # Regex ottimizzata per librerie di terze parti comuni
    LIBRARY_REGEX = re.compile(
        r"(jquery|bootstrap|popper|modernizr|require|lodash|underscore|moment|d3|highcharts|chart|"
        r"angular|vue|react|react-dom|font-awesome|select2|slick|owl|scrollmagic|gsap|animate|"
        r"google-analytics|gtag|gtm|analytics|pixel|adsbygoogle|recaptcha|wordpress|vimeo|youtube|"
        r"maps\.google|axios|sweetalert|tippy|flatpickr|swiper|glide|core-js|bluebird|crypto-js|"
        r"socket\.io|fingerprintjs|webfont|lazysizes|modernizr|hammer|clipboard|intro\.js)"
        r"([.-]\d+)*(\.min)?\.js",
        re.IGNORECASE
    )

    # CDN note per librerie standard
    LIBRARY_CDNS = [
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "unpkg.com",
        "jsdelivr.net",
        "google-analytics.com",
        "googletagmanager.com"
    ]

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
                  
            # Carica configurazione da file con fallback chain
            file_config = self.load_config("spider", scan_type)
            profile = {**self.DEFAULT_CONFIG, **file_config}
            
            self._execute_katana(url, profile, scan_type, base_domain)

        # Katana is resource-heavy: usa max_workers dal config globale
        global_scan_type = params.get("scan_type", "fast").lower()
        global_config = self.load_config("spider", global_scan_type)
        cfg_max_workers = global_config.get("max_workers", self.DEFAULT_CONFIG["max_workers"])
        max_workers = min(cfg_max_workers, len(targets) if targets else 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_process_target, url) for url in targets]
            done, _ = concurrent.futures.wait(futures)
            for f in done:
                try:
                    f.result()
                except Exception as e:
                    print(f"Errore in un thread Spider: {e}", file=sys.stderr)

    def _execute_katana(self, url: str, profile: Dict[str, Any], scan_type: str, base_domain: str) -> None:
        timeout_minutes = profile.get("timeout_minutes", 5)
        cmd = [
            self.katana_path,
            "-u", url,
            "-silent", "-jsonl",
            "-c", str(profile.get("rate", 300) if profile.get("rate", 300) > 0 else 50),
            "-d", str(profile.get("depth", 1)),
            "-ct", str(timeout_minutes * 60)
        ]
        
        # Feature flags dal config
        if profile.get("auto_form_fill", True):
            cmd.append("-aff")
        if profile.get("js_crawling", True):
            cmd.append("-jc")
        if profile.get("known_files", True):
            cmd.extend(["-kf", "all"])
             
        try:
             # Generoso timeout complessivo al processo, Katana ha timeout nativi sulle conn
             process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=(timeout_minutes * 60) + 60)
             
             raw_endpoints = set()
             raw_js_files = set()
             
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
                             # Normalizzazione Endpoint: Garantiamo che siano URL assoluti per la validazione successiva
                             if request_url.startswith('//'):
                                 scheme = urlparse(url).scheme or 'http'
                                 normalized_ep = f"{scheme}:{request_url}"
                             elif request_url.startswith('/'):
                                 normalized_ep = f"{url.rstrip('/')}{request_url}"
                             elif request_url.startswith('http'):
                                 normalized_ep = request_url
                             else:
                                 normalized_ep = f"{url.rstrip('/')}/{request_url}"
                                 
                             raw_endpoints.add(normalized_ep)
                             
                             # JS File Matcher
                             clean_q_url = request_url.split('?')[0].lower()
                             if clean_q_url.endswith('.js'):
                                 if request_url.startswith('//'):
                                     scheme = urlparse(url).scheme or 'http'
                                     normalized_js = f"{scheme}:{request_url}"
                                 elif request_url.startswith('/'):
                                     normalized_js = f"{url.rstrip('/')}{request_url}"
                                 elif request_url.startswith('http'):
                                     normalized_js = request_url
                                 else:
                                     normalized_js = f"{url.rstrip('/')}/{request_url}"
                                     
                                 raw_js_files.add(normalized_js)
                     except json.JSONDecodeError:
                         pass
             
             # Filtraggio Intelligente per il report (Display Results)
             display_js_files = []
             hidden_libraries_count = 0
             
             for js in raw_js_files:
                 is_library = False
                 parsed_js = urlparse(js)
                 
                 # Check 1: È un CDN noto?
                 if any(cdn in js for cdn in self.LIBRARY_CDNS):
                     is_library = True
                 
                 # Check 2: Matcha la regex delle librerie?
                 if not is_library and self.LIBRARY_REGEX.search(os.path.basename(parsed_js.path)):
                     is_library = True
                     
                 if is_library:
                     hidden_libraries_count += 1
                 else:
                     display_js_files.append(js)
             
             # Estrai le paths assolute per usarle come wordlist (solo path, es. /api/users)
             paths_only = set()
             for ep in raw_endpoints:
                 try:
                     parsed = urlparse(ep)
                     if parsed.path and parsed.path != "/":
                         path = parsed.path.rstrip('/') # Rimuovi trailing slash
                         if parsed.query:
                             query = parsed.query.split('#')[0]
                             path = f"{path}?{query}"
                         if path:
                             paths_only.add(path)
                 except: continue
             
             with self.lock:
                 self.results[url] = {
                     "base_domain": base_domain,
                     "endpoints_count": len(raw_endpoints),
                     "js_files_count": len(display_js_files),
                     "js_files": display_js_files, # Questa sarà validata dal main
                     "raw_js_files": list(raw_js_files), # Per JS Analyzer (completa)
                     "endpoints": list(raw_endpoints),   # Questa sarà validata dal main
                     "paths_wordlist": list(paths_only), # Per FFUF (completa)
                     "hidden_libraries_count": hidden_libraries_count
                 }
             print(f"[{url}] Spidering completato. {len(raw_endpoints)} endpoint trovati ({len(display_js_files)} file JS custom, {hidden_libraries_count} librerie filtrate).", file=sys.stderr)

        except subprocess.TimeoutExpired:
             print(f"[{url}] Timeout durante Spidering Katana.", file=sys.stderr)
             with self.lock:
                  self.results[url] = {"error": "Run Timeout"}
        except Exception as e:
             with self.lock:
                  self.results[url] = {"error": f"Katana crash: {str(e)}"}

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
