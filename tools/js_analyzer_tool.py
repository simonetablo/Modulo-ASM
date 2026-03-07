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

class JsAnalyzerTool(Tool):
    """
    Esegue analisi statica dell'AST Javascript usando jsluice (BishopFox).
    Estrae endpoint segreti, API paths e URL cablati nel file.
    """

    def __init__(self):
        super().__init__()
        self.results = {}
        self.lock = threading.Lock()
        
        self.jsluice_path = shutil.which("jsluice")
        if not self.jsluice_path:
            home_go_bin = os.path.expanduser("~/go/bin/jsluice")
            if os.path.exists(home_go_bin):
                self.jsluice_path = home_go_bin
            else:
                print("ATTENZIONE: Eseguibile 'jsluice' non trovato. L'analisi JS fallirà.", file=sys.stderr)

    def run(self, js_urls: List[str], params: Dict[str, Any] = None) -> None:
        """
        Esegue Jsluice sugli URL dei file Javascript forniti.
        Nota: Jsluice accetta sia file locali che URL attivi in input.
        """
        if not self.jsluice_path:
            print("ATTENZIONE: jsluice path non trovato.", file=sys.stderr)
            return

        if not js_urls:
            return

        def _process_js_batch(js_urls_batch: List[str]):
            cmd = [
                self.jsluice_path,
                "urls",
                "-u",
                "-c", "5" # Concorrenza interna bassa per essere WAF-friendly e non saturare i socket
            ] + js_urls_batch
            
            try:
                 process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=(len(js_urls_batch) // 10 * 30) + 30)
                 
                 if process.stdout:
                     # Jsluice produce JSONL di default
                     for line in process.stdout.strip().split('\n'):
                         if not line.strip():
                             continue
                         try:
                             obj = json.loads(line)
                             url_match = obj.get("url", "")
                             filename = obj.get("filename", "") # Corrisponde all'URL originario passato in js_urls_batch
                             
                             if url_match and filename:
                                 found_paths = set()
                                 
                                 if url_match.startswith('/') or url_match.startswith('http'):
                                     parsed = urlparse(url_match)
                                     if parsed.path and parsed.path != "/":
                                         p = parsed.path
                                         if parsed.query: p += f"?{parsed.query}"
                                         found_paths.add(p)
                                 elif ("/" in url_match and len(url_match) > 3) or url_match.startswith('api'):
                                     if not url_match.startswith('.'):
                                         found_paths.add(f"/{url_match}")
                                         
                                 if found_paths:
                                     base_domain = urlparse(filename).hostname
                                     if base_domain:
                                         with self.lock:
                                             if base_domain not in self.results:
                                                 self.results[base_domain] = set()
                                             self.results[base_domain].update(found_paths)
                         except json.JSONDecodeError:
                             pass

            except subprocess.TimeoutExpired:
                 print(f"[JSLUICE] Timeout analizzando un batch di {len(js_urls_batch)} file.", file=sys.stderr)
            except Exception as e:
                 print(f"[JSLUICE] Crash analizzando batch: {e}", file=sys.stderr)


        # batch di 50 per evitare ban rate-limiting e sovraccarico RAM dal parsing AST di JS enormi
        batch_size = 50
        batches = [js_urls[i:i + batch_size] for i in range(0, len(js_urls), batch_size)]
        
        max_workers = min(5, len(batches))
        print(f"Avvio Javascript Static Analysis (jsluice) su {len(js_urls)} file ({len(batches)} batch da max {batch_size})...", file=sys.stderr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_process_js_batch, batch) for batch in batches]
            done, _ = concurrent.futures.wait(futures)
            for f in done:
                try:
                    f.result()
                except Exception as e:
                    print(f"Errore in un thread JS Analyzer: {e}", file=sys.stderr)
            
        # Stampa riepilogo e converte i set in liste per la serializzazione JSON
        for d in list(self.results.keys()):
            self.results[d] = list(self.results[d])
            print(f"[{d}] JSLUICE: Trovati {len(self.results[d])} path unici hardcoded nei JS.", file=sys.stderr)

    def get_results(self) -> str:
        return json.dumps(self.results, indent=4)
