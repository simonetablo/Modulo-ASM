import json
import argparse
import sys
from typing import List, Dict, Any
from tools.nmap_tool import NmapTool
from tools.httpx_tool import HttpxTool

def main():
    """
    Punto di ingresso principale del modulo ASM.
    
    Questa funzione si occupa di:
    1. Parsing degli argomenti da riga di comando.
    2. Lettura dell'input (JSON) da file, stringa o stdin.
    3. Inizializzazione dei tool necessari (es. NmapTool).
    4. Esecuzione della scansione.
    5. Stampa dei risultati in formato JSON su stdout.
    """
    
    # Configurazione del parser degli argomenti
    parser = argparse.ArgumentParser(description='ASM Module Backend - Modulo di scansione')
    parser.add_argument('--input', type=str, help='Stringa JSON di input', required=False)
    parser.add_argument('--file', type=str, help='Percorso al file JSON di input', required=False)

    args = parser.parse_args()

    data = None
    
    # Logica per determinare la sorgente dell'input
    if args.input:
        # Caso 1: Input passato direttamente come stringa JSON via argomento --input
        try:
            data = json.loads(args.input)
        except json.JSONDecodeError as e:
            print(f"Errore nella decodifica del JSON di input: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.file:
        # Caso 2: Input letto da un file specificato via --file
        try:
            with open(args.file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Errore nella lettura del file di input: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Caso 3: Input letto dallo Standard Input (stdin)
        # Utile per il piping
        if not sys.stdin.isatty():
            try:
                content = sys.stdin.read()
                if content:
                    data = json.loads(content)
            except Exception as e:
                print(f"Errore nella lettura da stdin: {e}", file=sys.stderr)
                sys.exit(1)
    
    # Se nessun dato valido è stato caricato, stampa l'help ed esce
    if data is None:
        parser.print_help()
        sys.exit(1)

    # Estrazione dei domini e dei parametri dal JSON
    domains = data.get('domains', [])
    params = data.get('params', {})

    if not domains:
        print("Errore: Nessun dominio specificato nell'input.", file=sys.stderr)
        sys.exit(1)

    # Inizializzazione di nmap tool
    nmap_tool = NmapTool()

    # Esecuzione del tool: Il metodo run prende la lista dei domini e il dizionario dei parametri
    nmap_tool.run(domains, params)
    
    # Recupero dei risultati di Nmap
    nmap_results_json = nmap_tool.get_results()
    nmap_results = json.loads(nmap_results_json)
    
    # Analisi dei risultati per identificare target web (porte 80/443 aperte)
    web_targets = []
        
    for domain, data in nmap_results.items():
        # Salta se c'è stato un errore su questo dominio
        if "error" in data:
            continue
            
        # Controlla la presenza della sezione 'tcp' nei risultati di nmap
        if "tcp" in data:
            tcp_ports = data["tcp"]
            # Converte le chiavi delle porte in stringhe per confronto sicuro (json keys sono stringhe)
            # Nmap potrebbe restituire int o str, così facendo si evitano errori
            
            # Controllo porta 80 (HTTP)
            if "80" in tcp_ports:
                state = tcp_ports["80"].get("state")
                if state in ["open", "filtered", "open|filtered"]:
                    web_targets.append(f"http://{domain}")
                
            # Controllo porta 443 (HTTPS)
            if "443" in tcp_ports:
                state = tcp_ports["443"].get("state")
                if state in ["open", "filtered", "open|filtered"]:
                    web_targets.append(f"https://{domain}")

    final_results = {}
    
    # Processa i risultati per creare un JSON pulito e strutturato
    for domain, nmap_data in nmap_results.items():
        if "error" in nmap_data:
            final_results[domain] = {"error": nmap_data["error"]}
            continue

        # Recupera l'IP
        ip_address = None
        if "addresses" in nmap_data and "ipv4" in nmap_data["addresses"]:
            ip_address = nmap_data["addresses"]["ipv4"]
        
        # Struttura base per il dominio
        domain_result = {
            "ip": ip_address,
            "scan_type": params.get("scan_type", "fast"),
            "ports": [],
            "web_recon": {}
        }
        
        # Estrazione info porte
        if "tcp" in nmap_data:
            for port, info in nmap_data["tcp"].items():
                port_info = {
                    "port": port,
                    "service": info.get("name", "unknown"),
                    "state": info.get("state", "unknown"),
                    "product": info.get("product", ""),
                    "version": info.get("version", "")
                }
                domain_result["ports"].append(port_info)
        
        final_results[domain] = domain_result

    # Se sono state trovate target web, lancia httpx e integra i risultati
    if web_targets:
        print(f"Target web identificati per scansione HTTPX: {web_targets}", file=sys.stderr)
        httpx_tool = HttpxTool()
        httpx_tool.run(web_targets, params)
        httpx_results = httpx_tool.results
        
        # Integra i risultati di httpx nella struttura del dominio corrispondente
        for url, data in httpx_results.items():
            # Estrae il dominio dall'URL (es. http://example.com -> example.com)
            domain_key = url.replace("http://", "").replace("https://", "").split("/")[0]
            
            if domain_key in final_results:
                final_results[domain_key]["web_recon"][url] = data
            else:
                 pass

    else:
        print("Nessun target web (80/443) trovato per scansione HTTPX addizionale.", file=sys.stderr)
    
    # Output dei risultati finali aggregati
    print(json.dumps(final_results, indent=4))

if __name__ == "__main__":
    main()
