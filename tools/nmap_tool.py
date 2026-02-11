import nmap
import json
import sys
import socket
from typing import List, Dict, Any
from .base_tool import Tool

class NmapTool(Tool):
    """
    Implementazione del tool Nmap che estende la classe base Tool.
    Utilizza la libreria `python-nmap` per eseguire scansioni di rete.
    """

    def __init__(self):
        """
        Inizializza il NmapTool.
        Chiama il costruttore della superclasse e inizializza l'oggetto PortScanner di nmap.
        """
        super().__init__()
        # Inizializza l'oggetto PortScanner dalla libreria nmap, fondamentale per interagire con l'eseguibile nmap installato nel sistema
        try:
            self.nm = nmap.PortScanner()
            # DEBUG: Verifica che nmap sia stato trovato correttamente
            nmap_version = self.nm.nmap_version()
            print(f"DEBUG: Nmap trovato. Versione: {nmap_version}", file=sys.stderr)
        except nmap.PortScannerError:
            print("ERRORE: Nmap non trovato nel PATH.", file=sys.stderr)
            print("Assicurati che nmap sia installato e aggiunto al PATH di sistema.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Errore inatteso nell'inizializzazione di nmap: {e}", file=sys.stderr)
            sys.exit(1)

    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Esegue la scansione Nmap sui domini specificati.
        Configura gli argomenti di Nmap in base al parametro 'scan_type'.

        Args:
            domains (List[str]): Lista dei domini target.
            params (Dict[str, Any]): Parametri della scansione. Si aspetta una chiave 'scan_type'
                                     che può essere 'fast', 'accurate' o 'stealth'.
        """
        # Recupera il tipo di scansione dai parametri, default a 'fast' se non specificato
        scan_type = params.get('scan_type', 'fast')
        
        # Definisce gli argomenti da passare a Nmap in base al profilo di scansione scelto
        if scan_type == 'fast':
            # -F: Fast mode. Scansiona meno porte rispetto al default (le 100 più comuni).
            # -T4: Aggressive timing template. Velocizza la scansione riducendo i timeout.
            args = '-F -T4'
        elif scan_type == 'accurate':
            # -p-: Scansiona TUTTE le porte (da 1 a 65535).
            # -sV: Probe open ports. Tenta di determinare la versione del servizio in ascolto.
            # -sC: Utilizza script di default (equivalente a --script=default) per banner grabbing e vulnerabilità base.
            # -T3: Normal timing template. Un bilanciamento standard tra velocità e affidabilità.
            args = '-p- -sV -sC -T3'
        elif scan_type == 'stealth':
            # -sS: TCP SYN scan. Non completa la connessione TCP, più difficile da rilevare per alcuni firewall e logging system.
            # -T2: Polite timing template. Rallenta la scansione per consumare meno banda e risorse, riducendo la probabilità di essere bloccati da IDS/IPS.
            args = '-sS -T2'
        else:
            # Fallback al profilo 'fast' per tipi di scan non riconosciuti
            args = '-F -T4'

        for domain in domains:
            target_ip = None
            try:
                # Risoluzione DNS per ottenere l'IP del dominio prima della scansione, necessario in quanto python-nmap usa l'IP come chiave nei risultati
                target_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                print(f"ERRORE: Impossibile risolvere il dominio {domain}", file=sys.stderr)
                self.results[domain] = {"error": "Impossibile risolvere il nome a dominio (DNS Error)"}
                continue # Passa al prossimo dominio
            except Exception as e:
                self.results[domain] = {"error": f"Errore durante la risoluzione DNS: {str(e)}"}
                continue

            try:
                print(f"Avvio scansione su {domain} ({target_ip}) con argomenti: {args}", file=sys.stderr)
                
                # Esegue la scansione sull'IP risolto
                self.nm.scan(hosts=target_ip, arguments=args)
                
                # Memorizza i risultati.
                if target_ip in self.nm.all_hosts():
                    # Salva i risultati nel dizionario finale usando il NOME A DOMINIO come chiave
                    self.results[domain] = self.nm[target_ip]
                else:
                    self.results[domain] = {"error": "Host scansionato ma nessun risultato restituito (potrebbe essere down o filtrare i pacchetti)"}
                    
            except Exception as e:
                # Gestione generica delle eccezioni nmap
                self.results[domain] = {"error": str(e)}

    def get_results(self) -> str:
        """
        Returns:
            str: Una stringa JSON formattata con indentazione per leggibilità.
        """
        return json.dumps(self.results, indent=4)
