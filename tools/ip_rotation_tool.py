import socket
import threading
import time
import json
import sys
import dns.resolver
from typing import List, Dict, Any
from datetime import datetime
from .base_tool import Tool


class IPRotationTool(Tool):
    """
    Tool per il monitoraggio in background della rotazione degli IP dei domini target.
    Esegue risoluzioni DNS periodiche per rilevare se gli IP cambiano nel tempo.
    """

    def __init__(self, dns_resolvers: List[str] = None):
        """
        Inizializza il monitor con DNS resolvers configurabili.
        
        Args:
            dns_resolvers: Lista di DNS resolver IPs. Default: ['1.1.1.1', '8.8.8.8', '8.8.4.4']
        """
        super().__init__()
        self.dns_resolvers = dns_resolvers or ['1.1.1.1', '8.8.8.8', '8.8.4.4']
        self.monitoring_thread = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.ip_history = {}  # {domain: [(timestamp, ip), ...]}
        self.monitoring_active = False
        self.start_time = None
        self.min_duration = 0


    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Avvia il monitoraggio in background della rotazione IP.
        
        Args:
            domains: Lista di domini da monitorare
            params: Parametri di configurazione contenenti:
                - rotation_monitor.enabled: bool (default: True) - abilita/disabilita il monitoraggio
                - rotation_monitor.interval_seconds: int (default: 30) - intervallo tra le risoluzioni DNS
                - rotation_monitor.duration_seconds: int (default: 120) - durata MINIMA del monitoraggio
                  Il monitor continuerà oltre questa durata fino al completamento degli altri scan
        """
        rotation_config = params.get('rotation_monitor', {})
        
        # Verifica se il monitoraggio è abilitato
        if not rotation_config.get('enabled', True):
            print("IP rotation monitoring disabilitato.", file=sys.stderr)
            return
        
        interval = rotation_config.get('interval_seconds', 30) # intervallo tra le risoluzioni DNS
        duration = rotation_config.get('duration_seconds', 120) # durata MINIMA del monitoraggio
        
        self.start_monitoring(domains, interval, duration)

    def start_monitoring(self, domains: List[str], interval: int, duration: int) -> None:
        """
        Avvia il thread di monitoraggio con parametri espliciti.
        """
        # Salva il tempo di inizio e la durata minima per il controllo in stop()
        self.start_time = time.time()
        self.min_duration = duration
        
        print(f"Avvio monitoraggio rotazione IP: intervallo={interval}s, durata minima={duration}s", file=sys.stderr)
        
        # Avvia il thread di monitoraggio
        self.monitoring_thread = threading.Thread(
            target=self._monitor_loop,
            args=(domains, interval, duration),
            daemon=False  # Non daemon per poter attendere il completamento
        )
        self.monitoring_active = True
        self.monitoring_thread.start()


    def _monitor_loop(self, domains: List[str], interval: int, duration: int) -> None:
        """
        Loop principale del monitoraggio che esegue risoluzioni DNS periodiche.
        Il parametro 'duration' rappresenta il tempo MINIMO di monitoraggio.
        Il monitor continuerà a girare fino a quando non viene fermato esplicitamente
        tramite stop_event, anche se ha superato la durata minima.
        """
        start_time = time.time()
        observation_count = 0
        min_duration_reached = False
        
        while not self.stop_event.is_set():
            elapsed = time.time() - start_time
            
            # Segna quando la durata minima è stata raggiunta
            if not min_duration_reached and elapsed >= duration:
                min_duration_reached = True
                print(f"[IP Monitor] Durata minima ({duration}s) raggiunta. Continuo fino al completamento degli altri scan...", file=sys.stderr)
            
            observation_count += 1
            
            # Risolve ogni dominio
            for domain in domains:
                self._resolve_and_track(domain)
            
            # Attende l'intervallo prima della prossima osservazione
            # Usa wait invece di sleep per permettere interruzioni
            if self.stop_event.wait(timeout=interval):
                break  # Stop event è stato settato
        
        self.monitoring_active = False
        final_elapsed = time.time() - start_time
        print(f"Thread di monitoraggio IP terminato dopo {final_elapsed:.1f}s. Totale osservazioni: {observation_count}", file=sys.stderr)

    def _resolve_and_track(self, domain: str) -> None:
        """
        Risolve un dominio usando DNS resolver configurato e traccia l'IP nella cronologia.
        """
        try:
            # Usa i DNS resolver configurati invece di quelli di sistema
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = self.dns_resolvers
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, 'A')
            ip = str(answers[0])  # Prende il primo IP
            timestamp = datetime.utcnow().isoformat() + 'Z'
            
            with self.lock:
                if domain not in self.ip_history:
                    self.ip_history[domain] = []
                
                self.ip_history[domain].append((timestamp, ip))
                
                # Log solo se c'è un cambio di IP
                if len(self.ip_history[domain]) > 1:
                    prev_ip = self.ip_history[domain][-2][1]
                    if ip != prev_ip:
                        print(f"[IP Monitor] ⚠️  IP CHANGE detected for {domain}: {prev_ip} -> {ip}", file=sys.stderr)
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            # Errore di risoluzione DNS - ignora silenziosamente
            pass
        except Exception as e:
            print(f"[IP Monitor] Errore durante risoluzione di {domain}: {e}", file=sys.stderr)


    def stop(self) -> None:
        """
        Ferma il monitoraggio in modo graceful.
        - Se la durata minima non è stata raggiunta, attende fino al suo completamento
        - Segnala al thread di fermarsi (via stop_event)
        - Attende che il thread termini completamente prima di ritornare
        """
        # Attendi la durata minima se non ancora raggiunta
        if self.start_time and self.min_duration > 0:
            elapsed = time.time() - self.start_time
            remaining = self.min_duration - elapsed
            
            if remaining > 0:
                print(f"[IP Monitor] Attendo {remaining:.1f}s per raggiungere la durata minima...", file=sys.stderr)
                time.sleep(remaining)
        
        # Segnala al thread di fermarsi
        self.stop_event.set()
        
        # Attendi che il thread termini completamente (senza timeout)
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            print("In attesa del completamento del monitoraggio IP...", file=sys.stderr)
            self.monitoring_thread.join()

    def get_results(self) -> str:
        """       
        Returns:
            JSON string con i risultati per ogni dominio monitorato
        """
        with self.lock:
            results = {}
            
            for domain, history in self.ip_history.items():
                if not history:
                    results[domain] = {
                        "status": "insufficient_data",
                        "observations": 0,
                        "unique_ips": [],
                        "changes_detected": 0,
                        "monitoring_duration_seconds": 0
                    }
                    continue
                
                # Estrai informazioni dalla cronologia
                unique_ips = list(set(ip for _, ip in history))
                observations = len(history)
                
                # Conta i cambi di IP
                changes = 0
                for i in range(1, len(history)):
                    if history[i][1] != history[i-1][1]:
                        changes += 1
                
                # Determina lo status
                if observations < 2:
                    status = "insufficient_data"
                elif changes > 0:
                    status = "rotating"
                else:
                    status = "static"
                
                # Calcola durata del monitoraggio
                first_time = datetime.fromisoformat(history[0][0].replace('Z', '+00:00'))
                last_time = datetime.fromisoformat(history[-1][0].replace('Z', '+00:00'))
                duration = (last_time - first_time).total_seconds()
                
                results[domain] = {
                    "status": status,
                    "observations": observations,
                    "unique_ips": unique_ips,
                    "changes_detected": changes,
                    "monitoring_duration_seconds": round(duration, 1)
                }
            
            self.results = results
            return json.dumps(results, indent=4)
