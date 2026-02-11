ESEMPIO DI RECONNAISSANCE PIPELINE:

0. **_Seed Injection_** : Viene fornito in input un dominio
1. **_Scope Definition_**
   1. **Input validation + TLD extraction**: Il dominio viene validato sintatticamente e ne viene estratto il TLD. (libreria _tldextract_)
2. **_Subdomain Enumeration_** : Si cerca ogni sub-asset associato al dominio principale, filtrando concorrentemente i risultati per evitare falsi positivi dovuti a eventuali wildcards.
   1. **Passive enumeration**: Vengono effettuate query a datasets third-party senza interagire con l'infrastruttura target. (tool _subfinder_)
   2. **Active enumeration**: Vengono enumerati i subdomains con approccio brute-force basato su wordlists. La scelta della wordlist impatta fortemente tempo e risorse necessarie per questa fase. Di fondamentale importanza configurare il tool per effettaure un controllo sulle wildcards, così da ottenere un output pulito composto da soli subdomains validi, risolvibili e non wildcard (tool _puredns_)
   3. **Permutation scanning**: Vengono presi i risultati dell'active enumeration e su di essi si effettuano permutazioni che sono poi fornite in input a puredns per cercare ulteriori subdomains. (tool _alterX_)
   4. **Zone identification**: Vengono filtrati tra i risultati della fase precedente zone ad "alta entropia" e corrispondenti a keywords comuni.
   5. **Recursive active scanning**: Per ciascuno dei risultati del passo precedente viene spawnata una nuova istanza di puredns, permettendo al tool di ricalibrare la wildcard-detection. (tool _puredns_)
3. **_Infrastructure Mapping_**: Si passa alla ricerca degli asset esposti effettivamente posseduti dal target.
   1. **IP Resolution**: Vengono presi i subdomains ricavati dalla fase 2 e "risolti" in indirizzi IP. (tool _dnsx_)
   2. **IP filtering**: Vengono presi gli IP ricavati dalla fase precedente taggando quelli appartenenti a CDNs per evitare che venga effettuato su di essi port-scanning. (tool _cdncheck_)
   3. **ASN & Network discovery**: Vengono presi gli IP non taggati come CDN per ricavarne ASN e Organization Name, filtrando solo quelli la cui organizzazione corrisponde al target e ricavando di essi il realtivo IP range. (tool _asnmap_)
   4. **Reverse DNS sweep**: Vengono presi gli IP ranges ricavati dal passo precedente e scansionati per cercare eventuali asset non ancora individuati. Qualora ci fossero nuovi domini questi dovrebbero essere reinseriti nella fase 1. (tool _dnsx_)
4. **_Port & Service Discovery_**
   1. **Port Scanning**: Viene eseguito port scanning sugli IP range trovati precedentemente, possibilmente suddividendoli in più processi paralleli. Potrebbero essere previsti due tipi di scan, uno rapido sulle porte più comuni e uno completo su tutte e 65k le porte. Da valutare la logica secondo cui eseguire l'uno o l'altro (o quando eseguirli entrambi). (tool _naabu_)
   2. **Service Identification**: Viene eseguito un primo service discovery su tutte le porte aperte per ricavare il servizio specifico dietro la porta. (tool _fingerprintx_)
   3. **Web identification**: Viene eseguito una verifica rapida della liveness delle porte identificate come HTTP nel passo precedente (eventualmente anche delle porte non ancora identificate). (tool _httpx_)
5. **_Deeper Analysis_**
   1. **Deep scan**: Vengono contattate alcune porte identificate nei passi precedenti per un analisi più approfondita. La logica con cui vengono scelte tali porte potrebbe escludere i servizi Web e adattare le flag di nmap sulla base dei dati già raccolti. (tool _nmap_)
   2. **Web Enrichment**: Vengono analizzate più nel dettaglio le porte web di cui è stata verificata la liveness. (tool _httpx_)
   3. **EVENTUALE ENRICHMENT PER SERVIZI SPECIFICI CON TOOL DEDICATI**
6. **_Vulnerability Scanning_**
   1. **Template-based scanning**: I dati relativi ai servizi raccolti nei passi precedenti vengono utilizzati per eseguire controlli mirati sulle vulnerabilità. (tool _nuclei_)

TOOLS:

| Tool             | Role                                   | Strenght                                                                                                                         | Weaknesses                                                                                                                                                                                    | ASM integration                                                                            |
| ---------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **Subfinder**    | Passive subdomain enumeration          | Extremely fast, modular configuration, excellent API key management, standardized JSON output.                                   | Only finds what has already been indexed by third parties. Will not find new/hidden dev environments.                                                                                         | Primary driver to configure it with all available API keys.                                |
| **Amass**        | Active & passive subdomain enumeration | Unrivaled depth. It performs scraping, certificate analysis, and active graph mapping.                                           | resource-intensive and significantly slower than Subfinder. Its active scanning mode can be extremely noisy and trigger bans. Struggles with maintaining state in a simple stateless pipeline | Specialized for deep scans only, very comprehensive but too slow for real-time monitoring. |
| **Dnsx**         | Active subdomain enumeration           | Excels at probing specific records and outputting rich JSON, great for Reverse DNS lookups                                       | slower than PureDNS for raw brute-force                                                                                                                                                       | Use for Enrichment on already validated subdomains.                                        |
| **Puredns**      | Active subdomain enumeration           | Extremely fast, excellent for wildcard sanitization                                                                              | Requires a trusted list of resolvers to be effective                                                                                                                                          | Essential Core to use primarly for active enumeration and validation                       |
| **AlterX**       | Permutation engine                     | Its context-awareness enables it to learn patterns. It uses a DSL (Domain Specific Language) to create highly probable wordlists | Slower than simple string concatenation tools because of the pattern analysis overhead.                                                                                                       | Primary Generator. Smart generation saves hardware and network resources.                  |
| **Ripgen**       | Permutation engine                     | Extremely fast, brute force wordlist-based permutator                                                                            | Its "dumb" generation produce massive wordlists full of junk that risk to clog infrastructures.                                                                                               | Use only if there is unlimited bandwidth and zero constraints.                             |
| **Cndcheck**     | CDN/WAF detector                       | Uses a curated list of IP ranges to tell you if an IP is a "real" server or just a WAF/CDN node.                                 |                                                                                                                                                                                               | Critical Safety Filter to run before port scanning.                                        |
| **Asnmap**       | ASN reconnaissance                     | Instantly converts Organization Names in CIDR ranges. Excellent for finding "Shadow Infrastructure"                              |                                                                                                                                                                                               | Essential in shadow infrastructure discovery.                                              |
| **Naabu**        | Port scan                              | Very fast (SYN scan), can pipe input/output easily. Good for finding which ports are open.                                       | Bad at service identification, it just tells you the port is open, not what is running there                                                                                                  | Core Port Scanner to use to find open ports, then hand them off to other tools.            |
| **Fingerprintx** | Service identification                 | Designed to run after a port scan, much faster than nmap                                                                         | can be less precise and comprehensive than nmap                                                                                                                                               | Optimal for identifing services on non-HTTP ports rapidly.                                 |
| **Httpx**        | Service identification                 | Specific and extremely comprehensive for web probing.                                                                            |                                                                                                                                                                                               | Excellent for scanning any port identified as HTTP/HTTPS.                                  |
| **Nmap**         | Port scan & Service identification     | The only tool that reliably generates CPEs for CVE mapping. Unmatched accuracy for obscure protocols.                            | Very slow, hard to parse XML output efficiently in streaming pipelines.                                                                                                                       | To be used only where other service identificators fails or on very specific assets.       |
| **Nuclei**       | Vulnerability scan                     | Incredibly fast template-based, community-driven, JSON output. It finds exploitable bugs (CVEs, misconfigurations, token leaks)  | Only finds what is in its templates.                                                                                                                                                          | Core Component to be used as primary vulnerability scanner.                                |

- **nmap**: Ricerca live hosts sulla rete target, porte aperte, service versions, OS; LAYER 3/4 (estensibile a layer 7 grazie allo scripting engine NSE).
  Può operare con Raw Sockets se eseguito con privilegi di amministratore, craftando pacchetti bypassando le regole intrinseche dell'OS può risultare più stealth e granulare.
  Funzionamento sincrono e statefull, mantiene una internal table di ogni tentativo di connessione e il relativo risultato; in caso di mancata risposta riprova ad effettuare la scansione più volte in maniera dinamica prima di comunicare il risultato, gestendo ottimamente la natura best-effort "inaffidabie" della rete.  
  Molto lento e resource-intensive ma estremamente affidabile e granulare, offre la possibilità di eseguire custom detection logic e scripts grazie a NSE .
- **Masscan**: Alternativa asincrona e stateless a nmap con focus su throughput e velocità. Bypassa il kernel dell'OS nella gestione dei pacchetti effettuando injection di frames etherent appositamente costruiti direttamente nel network-card driver; bypassa inoltre il routing dell'OS gestendo direttamente il proprio ARP.
  La sua natura stateless permette di scansionare milioni di hosts al secondo: anzichè mantenere memoria dei pacchetti inviati a ciascun host utilizza "SYN-Cookies", craftando l'initial sequence number nei SYN packets non in maniera casuale ma utilizzando l'hash di informazioni utili a riconoscere l'eventuale risposta (SrcIP, DstIP, SrcPort, DstPort, Key) è in grado di verificare alla ricezione di una risposta SYN-ACK se questa è stata inviata in risposta a una probe di Masscan senza mantenere alcun dato in memoria relativo alle pending connections.
  La scansione di reti molto grandi viene gestita effettuando probes sugli indirizzi in ordine pseudo-random, sfruttando un Linear Congruential Generator (LCG), un algoritmo che cicla in un range di numeri in maniera pseudo-casuale ma assicurando nessuna ripetizione.
  Masscan include un custom TCP stack per eseguire banner-grabbing, anche se questo consuma molte più risorse del solo port-checking.
  Molto veloce, scala benissimo le performance su reti enormi ma rischia di causare DOS involontari e non gestisce l'eventualità di packet-drop. Molto più limitato di nmap, sopratutto per la mancanza di OS fingerprinting e scripting language.
- **RustScan**: La via di mezzo che coniuga l'efficienza dello scanning asincrono con la versatilità di tools statefull e sincroni. Realizzato in Rust sfrutta un architettura multi-thread per velocizzare gli scan, facendo però affidamento i socket standard dell'OS (non bypassa il kernel come Masscan).
  Implementa un meccanismo di "Adaptive Learning" che monitora l'RTT delle probe iniziali, aggiustando il timeout trashold e la batch size sulla base della velocità di risposta del target.
  Non è pensato per sostituire nmap ma per velocizzarlo: una volta eseguito lo "sweep" iniziale su tutte e 65535 porte utilizza comandi nmap per eseguire scan approfonditi sulle sole porte aperte.
  Velocizza sensibilmente lo scan mantenendo l'accuracy di nmap; può stressare eccessivamente il sistema operativo in quanto utilizza gli OS sockets; può aver difficoltà di accuratezza in reti congestionate a causa del batching aggressivo permesso dal multi-thread.
- **Naabu**: Simile per concezione a RustScan ma realizzato in Go (esegue esclusivamente una port enumeration). Gestisce ottimamente scan multi-threaded preferendo SYN-scan quando eseguito con privilegi di amministratore, craftrando appositi "raw" SYN-packets (high-speed, half-open scanning). Disaccoppia l'invio dalla ricezione dei pacchetti, rendendo lo scan asincrono e dunque aumentando il throughput (simile a Masscan).
  Prima di eseguire lo scan interroga l'API di Shodan InternetDB, evitando traffico inutile qualora Shodan avesse già eseguito uno scan sul target (meno rischio di congestione e più stealth).
  Accetta input da "stdin" e fornisce un output JSON, il che lo rende ottimo come "middleman" in catene automatizzate.
  Anche se veloce e abbastanza affidabile, con possibilità di avere un minore footprint attivo sul target, esegue solamente una port-enumeration, rendendo necessario l'utilizzo di altri tools (come nmap) per analisi più approfondite sugli host e le porte rilevati.
- **Scapy**: Non uno scanner in senso tradizionale ma un programma di manipolazione dei pacchetti realizzato in Python. Può poplare automaticamente alcuni campi ma permette all'occorrenza una manipolazione completa del pacchetto craftato.
  Questa sua complessità permette di definire logiche completamente customizzate e interazioni non-standard, ma comporta anche enorme overhead. Se utilizzato correttamente permette di evadere Firewalls e IDS come nessun altro tool.
  Benchè estremamente potente e flessibile la sua lentezza e complessità ne limitano l'utilizzo a target noti specifici.
- **MTR**: Industry standard tool per misurare l'affidabilità di un path specifico. Combina ping e traceroute per restituire latenza e packet loss a ciascun hop tra lo scanner e il target.
- **whatweb**: Software Stack detector. Invia richieste HTTP a un sito web e analizza le risposte. RUMOROSO
- **dig**: Interroga i server DNS. Può essere considerato attivo se usato contro i server DNS del target. Può ritornare DNS records, TTL informations e tracciare il path di DNS resolutions. POCO RUMOROSO.
- **netdiscover**: Cerca i live hosts all'interno della LAN; LAYER 2. Utilizza il protocollo ARP, ritornando IP, MAC address e MAC vendor dei dispositivi collegati alla rete locale. Può essere configurato per essere totalmente passivo, mettendosi in ascolto sulla rete per traffico ARP (scambiato ad esempio al collegamento di un dispositivo al wifi).
- **SSLyze**: Libreria python specializzata per lo scan SSL/TLS in grado di identificare con alta precisione misconfigurations in server SSL, anche in presenza di configurazioni aggiornate.
- **Katana**:
- **Netexec**: Specializzato nell'identificare target in ambienti Windows e active-directory, anche in presenza di versioni moderne (con le quali nmap rischia di non avere la stessa precisione).
- **wafw00f**: Utility dedicata a triggerare risposte dai Web Application Firewalls (WAF). E' in grado di indentificare precisamente molti WAF analizzando unicità negli header e comportamenti in presenza di errori.
- **FeroxBuster**: Esegue un subdirectory scan in maniera ricorsiva molto velocemente.
- **Ffuf**: Subdirectory scanner altamente flessibile e customizzabile.
- **OpenVAS**: Vulnerability scanner Open-Source. Non è un software monolitico ma un architettura basta su daemons comunicanti (più difficle da setuppare e più pesante sull'hardware).

SOLUZIONI IMPLEMENTATIVE :

_PIPELINES_

La soluzione migliore potrebbe essere quella di realizzare un modulo che orchestra diversi tools specializzati organizzati in pipeline, sfruttando i punti di forza di ciascuno.
La pipeline potrebbe essere differente a seconda del tipo di scan richiesto nella call API.
Da valutare uno scan dell'affidabilità della rete (ad esempio con MTR) per decidere automaticamente quali tools utilizzare.

_SCELTA DEI TOOLS_

Diverse metriche da considerare nella scelta dei tools:

- Precisione
- Rumorosità/Stealthiness
- risorse utilizzate
- Input accettato (formato e formattazione)
- Output restituito (formato e formattazione)

_API CALLS_

All'interno delle call API potrebbero essere inseriti parametri aggiuntivi (oltre al dominio target) per diverse tipologie di scan, ad esempio:

- Fast
- Comprehensive
- Stealth
- Noisy

_ORCHESTRATORE PYTHON_

_ACCORTEZZE_

- Ogni step di scansione dovrebbe essere inseirito in un modulo separato, ma probabilmente una totale modularità della pipeline sarebbe overkill, difficile da realizzare e debuggare e "fragile". Organizzando i moduli in pipelines predefinite si dovrebbe avere il giusto compromesso.
- Tool distinti restituiscono spesso risultati discordanti. Al posto di sovrascrivere i risultati dei tool precedenti con l'ultimo eseguito si può mantenere traccia dei risultati di ciascun tool.
- Si potrebbe implementare un sistema di confidence scoring per ciascun asset basato sui risultati indipendenti di ciascun tool (tool diversi o eseguiti con flag differenti in pipelines distinte possono restituire risultati contrastanti). In questo modo si evita di avere un "inventario" inaffidabile di risultati.
- Ha senso mantenere "snapshots" di ciascuno scan eseguito, eventualmente implementando un sistema per evidenziare le differenze tra lo scan attuale e i precedenti.
- Le varie pipelines potrebbero essere orchestrate per essere eseguite in sequenza secondo una determinata logica (che decide se, in che ordine e su quali asset eseguire le pipelines successive).
- Il modulo potrebbe essere pensato come una "state machine" per assets (dove per asset si intende un dominio, host, ip, port, service, application ecc.). Ciascun asset si muove attraverso diversi stati (ad esempio UNKNOWN > DISCOVERED > CONFIRMED > ENRICHED > AUDITED).
