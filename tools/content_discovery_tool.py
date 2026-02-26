import os
import json
import shutil
import subprocess
import sys
import concurrent.futures
from typing import List, Dict, Any
from .base_tool import Tool

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

    # Mappatura Tecnologie -> Wordlist Specifiche
    TECH_WORDLIST_MAP = {
        "wordpress": "wordlists/tech/wordpress.txt",
        "iis": "wordlists/tech/iis.txt",
        "asp.net": "wordlists/tech/iis.txt",
        "tomcat": "wordlists/tech/tomcat.txt",
        "apache": "wordlists/tech/apache.txt",
        "nginx": "wordlists/tech/nginx.txt",
        "spring": "wordlists/tech/spring.txt",
        "node.js": "wordlists/tech/nodejs.txt"
    }

    # Profili FFUF - Bilanciano aggressività, velocità e rate limiting
    SCAN_PROFILES = {
        "fast": {"threads": 50, "rate": 0, "timeout": 5},
        "accurate": {"threads": 30, "rate": 50, "timeout": 8},
        "comprehensive": {"threads": 40, "rate": 0, "timeout": 10},
        "stealth": {"threads": 5, "rate": 10, "timeout": 15},
        "noisy": {"threads": 100, "rate": 0, "timeout": 5}
    }

    def __init__(self, wordlist_path: str = None):
        """
        Inizializza ContentDiscoveryTool.
        Richiede l'eseguibile FFUF locale e una wordlist di directory/file valida.
        """
        super().__init__()
        self.results = {}
        
        self.ffuf_path = shutil.which("ffuf")
        if not self.ffuf_path:
            print("ATTENZIONE: Eseguibile 'ffuf' non trovato nel PATH. Content Discovery fallirà.", file=sys.stderr)
            
        # Default wordlist fornita all'utente o una fallback standard.
        # In un setup reale, scaricare wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt
        default_wordlists = [
            "wordlists/content_discovery.txt",
            "./wordlists/content_discovery.txt",
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


    def run(self, targets: List[str], params: Dict[str, Any], httpx_results: Dict[str, Any] = None, target_params: Dict[str, Dict] = None) -> None:
        """
        Esegue il Web Fuzzing Context-Aware sugli URL forniti.
        
        Args:
            targets (List[str]): URL da scansionare (es: http://example.com)
            params: Parametri globali
            httpx_results: Il sub-documento JSON contenente i tech tags (necessario per l'estrazione context-aware).
            target_params: Override dei profili per singoli root domains
        """
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

        def _process_target(url: str):
            print(f"[{url}] Setup Content Discovery (Context-Aware)...", file=sys.stderr)
            
            # 1. Determina il profilo di scansione
            clean_url = url.replace('http://', '').replace('https://', '')
            base_domain = clean_url.split('/')[0].split(':')[0]
            
            scan_type = target_params.get(base_domain, {}).get("scan_type", params.get("scan_type", "fast")).lower()
            if scan_type not in self.SCAN_PROFILES:
                 scan_type = "fast"
                 
            profile = self.SCAN_PROFILES[scan_type]
            
            # 2. Analisi Contestuale Httpx (Ricerca Tecnologie e Wordlist)
            extensions = self._calculate_extensions(url, httpx_results)
            tech_wordlists = self._calculate_tech_wordlists(url, httpx_results)
            
            # Se è stealth non aggiungiamo troppe estensioni per limitare le metriche di query
            if scan_type == "stealth" and len(extensions) > 1:
                extensions = extensions[:1]
                tech_wordlists = [] # Evita wordlist extra in stealth mode
                
            # Costruzione riga estensioni: " -e .php,.txt "
            ext_flag = ""
            if extensions:
                ext_flag = f"-e {','.join(extensions)}"
                print(f"[{url}] Tech rilevate. Aggiunte estensioni contestuali: {','.join(extensions)}", file=sys.stderr)
            else:
                print(f"[{url}] Nessuna tech specifica rilevata per estensioni.", file=sys.stderr)
                
            if tech_wordlists:
                print(f"[{url}] Trovate wordlist specifiche per la tech: {', '.join(tech_wordlists)}", file=sys.stderr)

            # 3. Costruzione e Lancio Comando FFUF
            self._execute_ffuf(url, ext_flag, profile, scan_type, tech_wordlists)

        max_workers = min(3, len(targets) if targets else 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_process_target, url) for url in targets]
            concurrent.futures.wait(futures)

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

    def _calculate_tech_wordlists(self, url: str, httpx_results: Dict[str, Any]) -> List[str]:
         """
         Mappa i tag "tech" dell'URL specificato allestendo un set deduplicato di wordlist specifiche.
         """
         wl_set = set()
         target_data = httpx_results.get(url, {})
         
         techs = target_data.get("tech", [])
         
         for tech in techs:
             tech_lower = tech.lower()
             
             for known_tech, mapped_wl in self.TECH_WORDLIST_MAP.items():
                  if known_tech in tech_lower:
                       if os.path.exists(mapped_wl):
                           wl_set.add(mapped_wl)
                       
         return list(wl_set)
         
    def _execute_ffuf(self, url: str, ext_flag: str, profile: Dict[str, Any], scan_type: str, tech_wordlists: List[str] = None) -> None:
        """
        Innesca il processo ffuf, parsando l'stdout line-by-line (formato JSON)
        ed accumulando i risultati validati nella directory.
        """
        # Assicuriamoci che l'url finisca con la keyword principale
        target_url = url if url.endswith('/') else f"{url}/"
        
        # Gestione avanzata multi-wordlist per evitare estensioni doppie.
        # W1 = Wordlist Generica (subisce le estensioni di -e, es: admin -> admin.php)
        # W2 = Wordlist Specifica (già provvista di estensioni, es: wp-login.php)
        
        if tech_wordlists:
            # RUN 1: Wordlist Base
            # Nei profili "fast" o "stealth", se abbiamo wordlists tecnologiche specifiche (W2),
            # saltiamo del tutto la ricerca generalista (W1) per risparmiare moltissimo tempo ed essere furtivi.
            if scan_type not in ["fast", "stealth"]:
                self._do_ffuf_run(target_url, [self.wordlist], ext_flag, profile, "Base + Estensioni")
            else:
                print(f"[{url}] Profilo '{scan_type}': Salto directory fuzzing generico, uso solo tech-words.", file=sys.stderr)
            
            # RUN 2: Wordlist Specifiche
            self._do_ffuf_run(target_url, tech_wordlists, "", profile, "Dizionari Tech")
            
        else:
            # Singola run normale se non ci sono tecnologie specifiche trovate
            self._do_ffuf_run(target_url, [self.wordlist], ext_flag, profile, "Singola")

    def _do_ffuf_run(self, base_url: str, wordlists: List[str], ext_flag: str, profile: Dict[str, Any], run_desc: str) -> None:
        """
        Esegue un singolo comando Ffuf
        """
        target_url = f"{base_url}FUZZ"
        wordlist_arg = f"{','.join(wordlists)}:FUZZ"
        
        # -s: silent, -ac: auto-calibration (rimuove i falsi positivi 200 OK wildcard), -json: output parsabile
        cmd = [
            self.ffuf_path,
            "-w", wordlist_arg,
            "-u", target_url,
            "-s", "-json", "-ac"
        ]
        
        if ext_flag:
            cmd.extend(["-e", ext_flag.replace("-e ", "").strip()])
            
        cmd.extend(["-t", str(profile["threads"])])
        cmd.extend(["-timeout", str(profile["timeout"])])
        
        if profile["rate"] > 0:
             cmd.extend(["-rate", str(profile["rate"])])

        try:
             # Esecuzione
             process = subprocess.run(cmd, capture_output=True, text=True, check=False)
             
             # FFuf stampa righe json in caso di risultati.
             findings = []
             if process.stdout:
                 try:
                     # L'output di -json standard in ffuf e' un unico grande JSON object.
                     obj = json.loads(process.stdout)
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
                 except json.JSONDecodeError:
                     # Fallback in caso stampi array misti
                     for line in process.stdout.strip().split('\n'):
                         if not line.strip():
                             continue
                         try:
                             obj = json.loads(line)
                             if "url" in obj and "status" in obj:
                                 findings.append(obj)
                         except json.JSONDecodeError:
                             pass
             
             if process.stderr:
                 pass # Ffuf stderr contains rate limiting logs in -ac mode, ignore it to keep clean logs
             
             base_url_clean = base_url.replace("FUZZ", "")
             if base_url_clean not in self.results:
                 self.results[base_url_clean] = []
             self.results[base_url_clean].extend(findings)
             print(f"[{base_url_clean}] Content Discovery run completata ({run_desc}). {len(findings)} path trovate.", file=sys.stderr)
             
        except Exception as e:
             base_url_clean = base_url.replace("FUZZ", "")
             if base_url_clean not in self.results:
                  self.results[base_url_clean] = []
             self.results[base_url_clean] = {"error": f"Ffuf crash: {str(e)}"}


    def get_results(self) -> str:
        """
        Ritorna l'output finale
        """
        return json.dumps(self.results, indent=4)
