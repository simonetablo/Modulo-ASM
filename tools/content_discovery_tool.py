import os
import json
import shutil
import subprocess
import sys
import threading
import concurrent.futures
import uuid
from typing import List, Dict, Any
from .base_tool import Tool, BASE_DIR

class ContentDiscoveryTool(Tool):
    """
    Esegue Context-Aware Content Discovery (Web Fuzzing) usando FFUF.
    Determina dinamicamente le estensioni da ricercare in base allo stack tecnologico individuato da Httpx.
    """

    # Mappatura Tecnologie -> Estensioni
    TECH_EXTENSION_MAP = {
        "php": [".php", ".txt", ".bak", ".old", ".zip"],
        "wordpress": [".php", ".txt", ".zip", ".sql"],
        "iis": [".asp", ".aspx", ".config", ".txt", ".bak"],
        "asp.net": [".asp", ".aspx", ".config", ".txt", ".bak"],
        "tomcat": [".jsp", ".xml", ".war", ".txt"],
        "spring": [".jsp", ".xml", ".properties"],
        "python": [".py", ".txt", ".bak"],
        "django": [".py", ".txt", ".sqlite"],
        "ruby": [".rb", ".txt"],
        "node.js": [".js", ".json", ".txt", ".bak"],
        "express": [".js", ".json", ".txt"],
        "apache": [".html", ".txt", ".bak", ".conf"],
        "nginx": [".html", ".txt", ".bak", ".conf"]
    }

    # WordlistManagerTool instance (optional)
    wl_manager = None

    # Profili FFUF - Parametri caricati da config/content_discovery/<scan_type>_config.json
    DEFAULT_CONFIG = {
        "threads": 50,
        "rate": 0,
        "timeout_minutes": 15,
        "recursion_depth": 0,
        "match_codes": "200,204,301,302,307,401,403,405",
        "max_workers": 3,
        "cdn_max_threads": 20,
        "cdn_forced_rate": 30
    }

    def __init__(self, wordlist_path: str = None):
        """
        Inizializza ContentDiscoveryTool.
        Richiede l'eseguibile FFUF locale e una wordlist di directory/file valida.
        """
        super().__init__()
        self.results = {}
        self.lock = threading.Lock()
        
        self.ffuf_path = shutil.which("ffuf")
        if not self.ffuf_path:
            print("ATTENZIONE: Eseguibile 'ffuf' non trovato nel PATH. Content Discovery fallirà.", file=sys.stderr)
            
        # Default wordlist fornita all'utente o una fallback standard.
        default_wordlists = [
            os.path.join(BASE_DIR, "wordlists", "content_discovery.txt"),
            os.path.expanduser("~/wordlists/content_discovery.txt"),
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
        ]
        
        self.wordlist = wordlist_path
        if not self.wordlist:
            for w in default_wordlists:
                if os.path.exists(w):
                    self.wordlist = w
                    break
                    
        if not self.wordlist:
             print("ATTENZIONE: Nessuna wordlist trovata nei path di default. Fornisci un file valido per il Web Fuzzing.", file=sys.stderr)


    def run(self, targets: List[str], params: Dict[str, Any], httpx_results: Dict[str, Any] = None, target_params: Dict[str, Dict] = None, dynamic_wordlists: Dict[str, List[str]] = None, wl_manager: Any = None) -> None:
        """
        Esegue il Web Fuzzing Context-Aware sugli URL forniti.
        
        Args:
            targets (List[str]): URL da scansionare (es: http://example.com)
            params: Parametri globali
            httpx_results: Il sub-documento JSON contenente i tech tags (necessario per l'estrazione context-aware).
            target_params: Override dei profili per singoli root domains
            dynamic_wordlists: Dizionario {base_domain: [paths...]} contenente i path trovati da Katana/Jsluice 
            wl_manager: Istanza di WordlistManagerTool per ottenere wordlist tecnologiche dinamiche
        """
        self.wl_manager = wl_manager
        if not self.ffuf_path:
            for t in targets:
                 self.results[t] = {"error": "ffuf non trovato nel PATH"}
            return
            
        if not self.wordlist:
             for t in targets:
                 self.results[t] = {"error": "Wordlist per Ffuf non trovata o specificata"}
             return

        if httpx_results is None:
             httpx_results = {}
        if target_params is None:
             target_params = {}
        if dynamic_wordlists is None:
             dynamic_wordlists = {}

        def _process_target(url: str):
            print(f"[{url}] Setup Content Discovery (Context-Aware)...", file=sys.stderr)
            
            # 1. Determina il profilo di scansione
            clean_url = url.replace('http://', '').replace('https://', '')
            base_domain = clean_url.split('/')[0].split(':')[0]
            
            domain_cfg = target_params.get(base_domain, {})
            scan_type = domain_cfg.get("scan_type", params.get("scan_type", "fast")).lower()
            max_rate = domain_cfg.get("max_rate", params.get("max_rate"))
            timing = domain_cfg.get("timing", params.get("timing", "normal"))
                 
            # Carica configurazione da file con fallback chain
            file_config = self.load_config("content_discovery", scan_type)
            profile = {**self.DEFAULT_CONFIG, **file_config}
            
            # 2. Analisi Contestuale Httpx (Ricerca Tecnologie e Wordlist)
            extensions = self._calculate_extensions(url, httpx_results)
            tech_wordlists = self._calculate_tech_wordlists(url, httpx_results, scan_type)
            
            # Se è stealth non aggiungiamo troppe estensioni per limitare le metriche di query
            if scan_type == "stealth" and len(extensions) > 1:
                extensions = extensions[:1]
                tech_wordlists = [] # Evita wordlist extra in stealth mode
                
            # Costruzione riga estensioni: " .php,.txt "
            ext_flag = ""
            if extensions:
                ext_flag = f"{','.join(extensions)}"
                print(f"[{url}] Tech rilevate. Aggiunte estensioni contestuali: {ext_flag}", file=sys.stderr)
            else:
                print(f"[{url}] Nessuna tech specifica rilevata per estensioni.", file=sys.stderr)
                
            if tech_wordlists:
                print(f"[{url}] Trovate wordlist specifiche per la tech: {', '.join(tech_wordlists)}", file=sys.stderr)

            # Leggi eventuale parametro custom per la profondità di ricorsione (fallback dal profilo scelto)
            default_depth = profile.get("recursion_depth", 1)
            recursion_depth = target_params.get(base_domain, {}).get("recursion_depth", params.get("recursion_depth", default_depth))

            # Controllo CDN per abbassare il rate limiting dinamicamente se non stealth o fast
            target_data = httpx_results.get(url, {})
            is_cdn = target_data.get("is_cdn", False) or target_data.get("cdn", False)
            
            # Se è dietro CDN e stiamo scansionando aggressivo, abbassiamo un po' i thread per non essere bloccati
            if is_cdn and scan_type in ["accurate", "comprehensive"]:
                 print(f"[{url}] CDN rilevata, autolimitazione dei thread temporanea per evitare ban WAF.", file=sys.stderr)
                 profile = profile.copy()
                 profile["threads"] = min(profile["threads"], profile.get("cdn_max_threads", 20))
                 if profile["rate"] == 0:
                      profile["rate"] = profile.get("cdn_forced_rate", 30)

            # Recupera l'eventuale wordlist dinamica (es. Spidering/JS) per questo dominio
            dyn_wl_file = None
            if base_domain in dynamic_wordlists and dynamic_wordlists[base_domain]:
                 paths = dynamic_wordlists[base_domain]
                 print(f"[{url}] Ricevuti {len(paths)} endpoint dinamici dallo spidering. Li converto in wordlist locale.", file=sys.stderr)
                 # Salva temporaneamente il set in \tmp (usa uuid per evitare race condition fra thread che scansionano sotto-dir dello stesso dominio)
                 dyn_wl_file = f"/tmp/asm_dyn_wl_{base_domain}_{uuid.uuid4().hex[:8]}.txt"
                 with open(dyn_wl_file, "w") as f:
                      for p in paths:
                           # Ffuf prepend the slash normally so we ensure paths don't start with / internally here to avoid double slash
                           clean_p = p.lstrip('/')
                           if clean_p:
                               f.write(f"{clean_p}\n")

            try:
                # 3. Costruzione e Lancio Comando FFUF
                self._execute_ffuf(url, ext_flag, profile, scan_type, recursion_depth, tech_wordlists, dyn_wl_file, max_rate=max_rate, timing=timing)
            finally:
                if dyn_wl_file and os.path.exists(dyn_wl_file):
                     try:
                         os.remove(dyn_wl_file)
                     except: pass

        # max_workers dal config globale
        global_scan_type = params.get("scan_type", "fast").lower()
        global_config = self.load_config("content_discovery", global_scan_type)
        cfg_max_workers = global_config.get("max_workers", self.DEFAULT_CONFIG["max_workers"])
        max_workers = min(cfg_max_workers, len(targets) if targets else 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_process_target, url) for url in targets]
            done, _ = concurrent.futures.wait(futures)
            for f in done:
                try:
                    f.result()
                except Exception as e:
                    print(f"Errore in un thread Content Discovery: {e}", file=sys.stderr)

    def _calculate_extensions(self, url: str, httpx_results: Dict[str, Any]) -> List[str]:
         """
         Mappa i tag "tech" dell'URL specificato allestendo un set deduplicato di estensioni.
         """
         ext_set = set()
         target_data = httpx_results.get(url, {})
         
         techs = target_data.get("tech", [])
         
         for tech in techs:
             tech_lower = tech.lower()
             
             # Cerca corrispondenze parziali nella mappa (es: "Apache HTTP Server" -> "apache")
             for known_tech, mapped_extensions in self.TECH_EXTENSION_MAP.items():
                  if known_tech in tech_lower:
                       ext_set.update(mapped_extensions)
                       
         return list(ext_set)

    def _calculate_tech_wordlists(self, url: str, httpx_results: Dict[str, Any], scan_type: str) -> List[str]:
         """
         Mappa i tag "tech" dell'URL specificato allestendo un set deduplicato di wordlist specifiche.
         """
         wl_set = set()
         if not self.wl_manager:
              return []

         target_data = httpx_results.get(url, {})
         techs = target_data.get("tech", [])
         
         deep_scan = scan_type in ["accurate", "comprehensive"]
         extra_techs_to_check = set()
         
         if deep_scan:
             for tech in techs:
                 tech_lower = tech.lower()
                 if "php" in tech_lower:
                     extra_techs_to_check.update(["wordpress"]) # Aggiunge WP bypassando la detection esplicita di httpx
                 elif "java" in tech_lower:
                     extra_techs_to_check.update(["tomcat", "spring"])
                  
         # Risoluzione tramite Wordlist Manager
         for tech in list(techs) + list(extra_techs_to_check):
              wl_path = self.wl_manager.get_wordlist("content_discovery", tech=tech)
              if wl_path and os.path.exists(wl_path):
                   # Evitiamo di inserire la wordlist base se è la stessa (poteva capitare col fallback a 'general')
                   if wl_path != os.path.abspath(self.wordlist):
                        if tech in extra_techs_to_check and tech not in techs:
                             print(f"[{url}] Deep scan: Aggiunta wordlist euristica per probabile {tech} derivato.", file=sys.stderr)
                        else:
                             print(f"[{url}] Trovata wordlist specifica per la tech: {tech}", file=sys.stderr)
                        wl_set.add(wl_path)
                        
         return list(wl_set)
         
    def _execute_ffuf(self, url: str, ext_flag: str, profile: Dict[str, Any], scan_type: str, recursion_depth: int, tech_wordlists: List[str] = None, dynamic_wordlist: str = None, max_rate: int = None, timing: str = "normal") -> None:
        """
        Innesca il processo ffuf, parsando l'stdout line-by-line (formato JSON)
        ed accumulando i risultati validati nella directory.
        """
        # Assicuriamoci che l'url finisca con la keyword principale
        target_url = url if url.endswith('/') else f"{url}/"
        
        # Gestione avanzata multi-wordlist per evitare estensioni doppie.
        # W1 = Wordlist Generica (subisce le estensioni di -e, es: admin -> admin.php)
        # W2 = Wordlist Specifica (già provvista di estensioni, es: wp-login.php)
        # W3 = Wordlist Dinamica da Katana/Jsluice 
        
        if dynamic_wordlist:
             # RUN SPECIALE: Fuzzing attivo chirurgico sui path trovati dallo spidering
             # Lo spidering trova il path "pulito", Ffuf proverà ad appendere le estensioni scoperte (es: /api/users -> /api/users.bak)
             self._do_ffuf_run(url, target_url, [dynamic_wordlist], ext_flag, profile, scan_type, recursion_depth, "Spidering Context", max_rate=max_rate, timing=timing)
        
        if tech_wordlists:
            # RUN 1: Wordlist Base
            # Nei profili "fast" o "stealth", se abbiamo wordlists tecnologiche specifiche (W2),
            # saltiamo del tutto la ricerca generalista (W1) per risparmiare moltissimo tempo ed essere furtivi.
            if scan_type not in ["fast", "stealth"]:
                self._do_ffuf_run(url, target_url, [self.wordlist], ext_flag, profile, scan_type, recursion_depth, "Base + Estensioni", max_rate=max_rate, timing=timing)
            else:
                print(f"[{url}] Profilo '{scan_type}': Salto directory fuzzing generico, uso solo tech-words.", file=sys.stderr)
            
            # RUN 2: Wordlist Specifiche
            self._do_ffuf_run(url, target_url, tech_wordlists, "", profile, scan_type, recursion_depth, "Dizionari Tech", max_rate=max_rate, timing=timing)
            
        else:
            # Singola run normale se non ci sono tecnologie specifiche trovate
            self._do_ffuf_run(url, target_url, [self.wordlist], ext_flag, profile, scan_type, recursion_depth, "Singola", max_rate=max_rate, timing=timing)

    def _do_ffuf_run(self, original_url: str, base_url: str, wordlists: List[str], ext_flag: str, profile: Dict[str, Any], scan_type: str, recursion_depth: int, run_desc: str, max_rate: int = None, timing: str = "normal") -> None:
        """
        Esegue un singolo comando Ffuf
        """
        target_url = f"{base_url}FUZZ"
        
        # -s: evita che il progress bar rompa il JSON su stdout
        # -ac: auto-calibration (filtra i falsi positivi wildcard)
        # -mc: espliciti status code validi invece di "all" per evitare inquinamento da WAF 403 bulk
        # -json: output parsabile come singolo JSON object
        cmd = [
            self.ffuf_path,
            "-u", target_url,
            "-s", "-json", "-ac", "-mc", profile.get("match_codes", "200,204,301,302,307,401,403,405")
        ]
        
        for wl in wordlists:
            cmd.extend(["-w", f"{wl}:FUZZ"])
        
        if ext_flag:
            cmd.extend(["-e", ext_flag])
            
        cmd.extend(["-t", str(profile["threads"])])
        
        # Aggiunta di -maxtime nativo di Ffuf per non bruciare risorse su host impiccati
        timeout_val = profile.get("timeout_minutes", 5) * 60
        cmd.extend(["-maxtime", str(timeout_val)])
        
        if max_rate:
             cmd.extend(["-rate", str(max_rate)])
        elif timing == 'polite':
             cmd.extend(["-rate", "10"])
        elif profile.get("rate", 0) > 0:
             cmd.extend(["-rate", str(profile["rate"])])

        # Aggiunta di Recursive Fuzzing se abilitato e solo su dizionari non mirati
        if "Base" in run_desc and recursion_depth > 0:
             cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
             if "-rate" not in cmd:
                 cmd.extend(["-rate", "100"]) # Non sfondare il server in recursione

        try:
             # Esecuzione subprocess leggermente più lasca del maxtime di ffuf
             process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_val + 30)
             
             # FFuf stampa righe json in caso di risultati.
             findings = []
             if process.stdout:
                  content = process.stdout.strip()
                  try:
                      # 1. Tentativo parsing unico blocco JSON
                      json_start = content.find('{')
                      if json_start != -1:
                          try:
                              obj = json.loads(content[json_start:])
                              if "results" in obj:
                                   for match in obj["results"]:
                                        findings.append({
                                            "endpoint": match.get("url", ""),
                                            "status": match.get("status", 0),
                                            "length": match.get("length", 0),
                                            "words": match.get("words", 0),
                                            "lines": match.get("lines", 0),
                                            "content_type": match.get("content-type", "")
                                        })
                          except json.JSONDecodeError as e:
                              if "Extra data" in str(e): raise e
                              print(f"[{url}] Errore parsing unico JSON: {e}", file=sys.stderr)

                  except json.JSONDecodeError:
                      # 2. Fallback: Parsing JSONL
                      for line in content.splitlines():
                          line = line.strip()
                          if not line.startswith('{'): continue
                          try:
                              match = json.loads(line)
                              if "url" in match:
                                   findings.append({
                                       "endpoint": match.get("url", ""),
                                       "status": match.get("status", 0),
                                       "length": match.get("length", 0),
                                       "words": match.get("words", 0),
                                       "lines": match.get("lines", 0),
                                       "content_type": match.get("content-type", "")
                                   })
                          except json.JSONDecodeError:
                              continue
             
             # Logica di deduplicazione: evitare doppi accodamenti dello stesso endpoint
             with self.lock:
                 if original_url not in self.results:
                     self.results[original_url] = []
                     
                 # Estrae tutti gli endpoint già presenti per questo url
                 existing_endpoints = {f["endpoint"] for f in self.results[original_url] if isinstance(f, dict) and f.get("endpoint")}
                 
                 unique_findings = []
                 for f in findings:
                     if f.get("endpoint") and f["endpoint"] not in existing_endpoints:
                         unique_findings.append(f)
                         existing_endpoints.add(f["endpoint"])
                         
                 self.results[original_url].extend(unique_findings)
             print(f"[{original_url}] Content Discovery run completata ({run_desc}). {len(unique_findings)} path uniche aggiunte (su {len(findings)} rilevate).", file=sys.stderr)

        except subprocess.TimeoutExpired:
             print(f"[{original_url}] Timeout durante Content Discovery ({run_desc}).", file=sys.stderr)
             with self.lock:
                  if original_url not in self.results:
                       self.results[original_url] = []
                  self.results[original_url].append({"error": f"Run Timeout ({run_desc})"})
             
        except Exception as e:
             with self.lock:
                  if original_url not in self.results:
                       self.results[original_url] = []
                  self.results[original_url].append({"error": f"Ffuf crash [{run_desc}]: {str(e)}"})


    def get_results(self) -> str:
        """
        Ritorna l'output finale
        """
        return json.dumps(self.results, indent=4)
