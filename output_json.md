# Struttura del JSON di Output — Modulo ASM

Documentazione completa della struttura del file JSON prodotto dal modulo `main.py`.
Il file viene salvato come `asm_results_YYYYMMDD_HHMMSS.json` e stampato su `stdout`.

---

## Indice

1. [Schema Top-Level](#1-schema-top-level)
2. [`scan_start` / `scan_end` / `total_duration`](#2-scan_start--scan_end--total_duration)
3. [`phase_timings`](#3-phase_timings)
4. [`scan_parameters`](#4-scan_parameters)
5. [`arguments`](#5-arguments)
6. [`targets`](#6-targets)
   - 6.1 [Target Safe (analizzato)](#61-target-safe-analizzato)
   - 6.2 [Target Skipped (scartato)](#62-target-skipped-scartato)
7. [Dettaglio campi per target safe](#7-dettaglio-campi-per-target-safe)
   - 7.1  [`ip`](#71-ip)
   - 7.2  [`scan_type`](#72-scan_type)
   - 7.3  [`infrastructure`](#73-infrastructure)
   - 7.4  [`origin_ip_bypass`](#74-origin_ip_bypass)
   - 7.5  [`safety_check`](#75-safety_check)
   - 7.6  [`scan_params_applied`](#76-scan_params_applied)
   - 7.7  [`subdomain_enum`](#77-subdomain_enum)
   - 7.8  [`ports`](#78-ports)
   - 7.9  [`web_recon`](#79-web_recon)
   - 7.10 [`spidering`](#710-spidering)
   - 7.11 [`js_analysis`](#711-js_analysis)
   - 7.12 [`advanced_fingerprint`](#712-advanced_fingerprint)
   - 7.13 [`content_discovery`](#713-content_discovery)
   - 7.14 [`vhost_enum`](#714-vhost_enum)
   - 7.15 [`ip_rotation`](#715-ip_rotation)

---

## 1. Schema Top-Level

```json
{
    "scan_start": "...",
    "scan_end": "...",
    "total_duration": "...",
    "phase_timings": { ... },
    "scan_parameters": { ... },
    "arguments": { ... },
    "targets": { ... }
}
```

**Dove viene creato:** `main.py`, funzione `main()`, linee 804-812, nel dizionario `global_results`.

**Perché:** La struttura top-level separa i metadati della scansione (durate, parametri, argomenti CLI) dai risultati effettivi per-target. Questo facilita il parsing automatico e l'analisi post-scansione.

---

## 2. `scan_start` / `scan_end` / `total_duration`

| Campo | Tipo | Esempio | Descrizione |
|---|---|---|---|
| `scan_start` | `string` | `"2026-03-09 15:47:55"` | Timestamp inizio scansione (formato `%Y-%m-%d %H:%M:%S`) |
| `scan_end` | `string` | `"2026-03-09 16:00:00"` | Timestamp fine scansione |
| `total_duration` | `string` | `"0:12:04"` | Durata totale nel formato `H:MM:SS` |

**Dove viene creato:** `main.py`, linee 494 (`start_time`), 799-801 (`end_time`, `duration_str`).

**Come:** `start_time = datetime.now()` all'inizio di `main()`, `end_time = datetime.now()` dopo tutte le fasi. La durata viene calcolata per sottrazione e formattata rimuovendo i microsecondi.

**Perché:** Permette di tracciare la finestra temporale esatta della scansione e la durata complessiva per benchmarking e correlazione con altri log.

---

## 3. `phase_timings`

```json
"phase_timings": {
    "subdomain_enumeration": 43.4,
    "infrastructure_analysis": 0.86,
    "port_scanning": 17.21,
    "web_recon": 406.64,
    "content_discovery": 215.22,
    "vhost_enumeration": 41.39
}
```

| Campo | Tipo | Descrizione |
|---|---|---|
| `subdomain_enumeration` | `float` | Durata Fase 1 (secondi) — puredns + AlterX + double check |
| `infrastructure_analysis` | `float` | Durata Fase 2 (secondi) — cdncheck + origin IP + safety |
| `port_scanning` | `float` | Durata Fase 3 (secondi) — nmap |
| `web_recon` | `float` | Durata Fase 4 (secondi) — httpx + nuclei |
| `content_discovery` | `float` | Durata Fase 5 (secondi) — katana + jsluice + ffuf |
| `vhost_enumeration` | `float` | Durata Fase 6 (secondi) — vhost ffuf |

**Dove viene creato:** `main.py`, linee 495, 614, 623, 655, 660, 667, 674. Ogni fase è cronometrata con `time.time()` e aggiunta al dizionario `phase_timings`.

**Perché:** Permette di identificare colli di bottiglia nella pipeline e ottimizzare le scansioni future. Utile per SLA e reportistica.

---

## 4. `scan_parameters`

```json
"scan_parameters": {
    "scan_type": "fast",
    "skip_nuclei": false,
    "skip_content_discovery": true,
    "rotation_monitor": {
        "enabled": true,
        "interval_seconds": 10,
        "duration_seconds": 30
    }
}
```

**Dove viene creato:** `main.py`, linea 809: `"scan_parameters": params`. Il dizionario `params` viene inizialmente letto dal JSON di input (`data.get('params', {})`, linea 562), poi viene arricchito con eventuali override da CLI (linee 566-595).

**Contenuto:** Contiene **tutti** i parametri operativi della scansione, sia quelli forniti nel file JSON di input sia quelli sovrascritti via flag CLI. I campi possibili includono:

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `scan_type` | `string` | `"fast"` | Profilo di aggressività: `fast`, `accurate`, `comprehensive`, `stealth` |
| `max_depth` | `int` | `5` | Profondità massima subdomain enumeration |
| `smart` | `bool` | `true` | Abilita smart permutations (micro-permutazioni in-loop) |
| `max_wildcards` | `int` | `5` | Limite variabili per AlterX |
| `timing` | `string` | `"normal"` | Timing Nmap: `normal` o `polite` |
| `max_rate` | `int\|null` | `null` | Rate limit pacchetti per Nmap/Nuclei |
| `skip_nuclei` | `bool` | `false` | Se `true`, salta la fase Nuclei |
| `skip_content_discovery` | `bool` | `false` | Se `true`, salta la fase Content Discovery (FFUF) |
| `recursion_depth` | `int` | `0` | Profondità di ricorsione per FFUF |
| `wordlist` | `string` | `"wordlists/subdomains.txt"` | Wordlist per subdomain bruteforce |
| `common_wordlist` | `string` | `"wordlists/common.txt"` | Wordlist per permutazioni AlterX |
| `vhost_wordlist` | `string` | `"wordlists/vhosts.txt"` | Wordlist per virtual host enumeration |
| `rotation_monitor` | `object` | — | Configurazione IP rotation monitoring (vedi sotto) |

### Sottooggetto `rotation_monitor`

| Campo | Tipo | Default | Descrizione |
|---|---|---|---|
| `enabled` | `bool` | `true` | Abilita il monitoraggio in background della rotazione IP |
| `interval_seconds` | `int` | `10` | Intervallo tra le risoluzioni DNS periodiche (secondi) |
| `duration_seconds` | `int` | `30` | Durata minima del monitoraggio (secondi) |

**Perché:** Documenta nel JSON di output la configurazione esatta con cui è stata eseguita la scansione, rendendo i risultati riproducibili e auditabili.

---

## 5. `arguments`

```json
"arguments": {
    "input": null,
    "file": "./test_real.json",
    "use_doh": false,
    "dns_proxy": null,
    "skip_content_discovery": false,
    "skip_nuclei": false,
    "output_dir": "."
}
```

**Dove viene creato:** `main.py`, linea 810: `"arguments": vars(args)`. Usa `vars()` sull'oggetto `argparse.Namespace` per serializzare tutti i flag CLI in un dizionario piatto.

**Contenuto:** Tutti i flag CLI passati al modulo:

| Campo | Tipo | Descrizione |
|---|---|---|
| `input` | `string\|null` | Stringa JSON inline passata via `--input` |
| `file` | `string\|null` | Percorso al file JSON di input passato via `--file` |
| `use_doh` | `bool` | Se `true`, usa DNS-over-HTTPS per la validazione finale |
| `dns_proxy` | `string\|null` | Percorso a un file con lista proxy per DoH |
| `skip_content_discovery` | `bool\|null` | Override CLI per skip content discovery |
| `skip_nuclei` | `bool\|null` | Override CLI per skip nuclei |
| `output_dir` | `string` | Directory di output per il file JSON finale |
| `scan_type` | `string\|null` | Override CLI del profilo di scansione |
| `max_depth` | `int\|null` | Override CLI profondità subdomain enum |
| `smart` | `bool\|null` | Override CLI per smart permutations |
| `max_wildcards` | `int\|null` | Override CLI per AlterX |
| `timing` | `string\|null` | Override CLI per timing Nmap |
| `max_rate` | `int\|null` | Override CLI per rate limit |
| `recursion_depth` | `int\|null` | Override CLI profondità ricorsione FFUF |
| `subdomains_wordlist` | `string\|null` | Override CLI wordlist sottodomini |
| `permutations_wordlist` | `string\|null` | Override CLI wordlist permutazioni |
| `vhost_wordlist` | `string\|null` | Override CLI wordlist vhosts |
| `rotation_enabled` | `bool\|null` | Override CLI abilitazione rotation monitor |
| `rotation_interval` | `int\|null` | Override CLI intervallo monitoring |
| `rotation_duration` | `int\|null` | Override CLI durata monitoring |

**Perché:** Registra i flag esatti usati per invocare il modulo, a differenza di `scan_parameters` che contiene il merge finale. Utile per audit e riproduzione esatta dell'invocazione.

---

## 6. `targets`

```json
"targets": {
    "mail.example.com": { ... },      // Target safe (analizzato)
    "unsafe.example.com": { ... }      // Target skipped (scartato)
}
```

**Dove viene creato:** `main.py`, linee 685-796. Il dizionario `final_results` viene popolato iterativamente da tutte le 6 fasi e poi assegnato come `"targets": final_results` nella struttura globale (linea 811).

**Chiave:** Ogni chiave è il nome di dominio (FQDN) del target. Include sia i domini originali dalla `target_list` che tutti i sottodomini scoperti durante la Fase 1.

---

### 6.1 Target Safe (analizzato)

Un target che ha superato tutti i safety checks e viene scansionato dalla pipeline completa. Struttura:

```json
"mail.example.com": {
    "ip": "212.25.183.115",
    "scan_type": "fast",
    "infrastructure": { ... },
    "origin_ip_bypass": { ... },
    "safety_check": { ... },
    "scan_params_applied": { ... },
    "subdomain_enum": { ... },
    "ports": [ ... ],
    "web_recon": { ... },
    "spidering": { ... },
    "js_analysis": { ... },
    "advanced_fingerprint": [ ... ],
    "content_discovery": [ ... ],
    "vhost_enum": { ... },
    "ip_rotation": { ... }
}
```

**Dove viene creato:** `main.py`, linee 688-724. Ogni target safe è inizializzato con valori di default vuoti, poi arricchito nelle linee 737-796.

---

### 6.2 Target Skipped (scartato)

Un target che non ha superato i safety checks (IP privato, errore DNS, fuori scope, ecc.).

```json
"unsafe.example.com": {
    "skipped": true,
    "reasons": ["Private IP address"],
    "warnings": [],
    "infrastructure": { ... },
    "safety_check": { ... }
}
```

| Campo | Tipo | Descrizione |
|---|---|---|
| `skipped` | `bool` | Sempre `true` per target scartati |
| `reasons` | `array[string]` | Motivi dello scarto (es. `"Private IP address"`, `"Infrastructure Error: DNS Resolution Failed"`) |
| `warnings` | `array[string]` | Avvertimenti non bloccanti |
| `infrastructure` | `object` | Dati infrastrutturali parziali (se disponibili) |
| `safety_check` | `object` | Risultato del safety check |

**Dove viene creato:** `main.py`, linee 727-734 (e linee 214-236 per la raccolta dei motivi nella fase 2).

**Perché:** Garantisce che **tutti** i target analizzati (anche quelli scartati) siano presenti nel JSON, con il motivo dello scarto per trasparenza e debugging.

---

## 7. Dettaglio campi per target safe

### 7.1 `ip`

```json
"ip": "212.25.183.115"
```

| Tipo | Descrizione |
|---|---|
| `string\|null` | Indirizzo IPv4 risolto per il dominio target |

**Dove viene creato:** `main.py`, linea 689, letto da `domain_ip_map` che è costruito da `HostingIntelTool` (`tools/hosting_intel_tool.py`, linea 98, 137: `self.results['_ip_map'] = domain_ip_map`).

**Come:** `HostingIntelTool.run()` esegue query DNS (record A) per ogni dominio usando resolver multipli con fallback e timeout configurabili. Il primo record A restituito diventa l'IP associato.

**Perché:** L'IP è il dato fondamentale per la deduplicazione in Nmap (non scansionare lo stesso IP due volte) e per tutti i check infrastrutturali.

---

### 7.2 `scan_type`

```json
"scan_type": "fast"
```

| Tipo | Descrizione |
|---|---|
| `string` | Profilo di scansione applicato: `fast`, `accurate`, `comprehensive`, `stealth` |

**Dove viene creato:** `main.py`, linea 694: `params.get("scan_type", "fast")`.

**Perché:** Registra il profilo di aggressività con cui il target è stato effettivamente scansionato. Influenza i parametri di Nmap, Nuclei, FFUF, Katana e l'analisi DNS.

---

### 7.3 `infrastructure`

```json
"infrastructure": {
    "has_infrastructure": false,
    "type_details": {},
    "is_dynamic": true,
    "ttl": 203,
    "ip_pool_size": 1
}
```

| Campo | Tipo | Descrizione |
|---|---|---|
| `has_infrastructure` | `bool` | `true` se l'IP è dietro CDN/WAF/Cloud |
| `type_details` | `object` | Dettagli del tipo di infrastruttura rilevata |
| `type_details.cdn` | `string` | Nome del provider CDN (es. `"Cloudflare"`) |
| `type_details.cloud` | `string` | Nome del provider Cloud (es. `"Amazon"`) |
| `type_details.waf` | `string` | Nome del WAF (es. `"Cloudflare"`) |
| `is_dynamic` | `bool` | `true` se l'IP sembra ruotare (TTL basso o pool > 1) |
| `ttl` | `int\|null` | Time-To-Live del record DNS A (secondi) |
| `ip_pool_size` | `int` | Numero di record A restituiti dalla query DNS |

**Dove viene creato:**
- `tools/hosting_intel_tool.py`, funzione `run()` (linee 36-137): Risoluzione DNS + cdncheck.
- `tools/hosting_intel_tool.py`, funzione `_run_cdncheck()` (linee 139-198): Analisi CDN/WAF/Cloud via tool `cdncheck`.
- `tools/hosting_intel_tool.py`, funzione `_check_ip_rotation()` (linee 200-219): Euristica rotazione IP basata su TTL e pool size.
- Linea 695 di `main.py` per l'assegnazione al target.

**Come:** Il tool esegue `cdncheck` (ProjectDiscovery) sugli IP unici per identificare CDN/WAF/Cloud provider. In parallelo, analizza il TTL e il numero di record A per determinare se l'IP è dinamico (TTL < 300s o pool_size > 1).

**Perché:** Determinare se un target è dietro CDN/WAF è cruciale per:
- Decidere se cercare degli Origin IP (bypass CDN)
- Calibrare i parametri di scansione (rate limiting per WAF)
- Segnalare l'infrastruttura nel report finale

---

### 7.4 `origin_ip_bypass`

```json
"origin_ip_bypass": {
    "origin_ips": ["185.10.20.30"],
    "cdn_ips": ["104.16.132.229"],
    "is_behind_cdn": true
}
```

oppure `{}` se non è dietro CDN.

| Campo | Tipo | Descrizione |
|---|---|---|
| `origin_ips` | `array[string]` | IP reali del server (dietro la CDN) confermati dalla validazione |
| `cdn_ips` | `array[string]` | IP associati alla CDN/WAF |
| `is_behind_cdn` | `bool` | `true` se il dominio base usa CDN/WAF/Cloud |

**Dove viene creato:** `tools/origin_ip_tool.py`, funzione `run()` (linee 58-118). Assegnato in `main.py` linea 696.

**Come:** `OriginIpTool` opera a livello di **dominio base** (raggruppando i sottodomini). Se il dominio base è dietro CDN ma alcuni sottodomini risolvono su IP **non-CDN**, questi IP vengono considerati candidati origin. La validazione è a cascata:
1. **Fast Probe** (httpx) — elimina IP che non rispondono
2. **SSL Validation** — verifica che il certificato contenga il dominio nei SAN/CN
3. **HTTP Validation** — confronto header signatures + body similarity (difflib, soglia 85%) con il sito pubblico

**Perché:** Trovare gli origin IP è il cuore dell'ASM offensivo: permette di bypassare le protezioni CDN/WAF e raggiungere direttamente il server backend.

---

### 7.5 `safety_check`

```json
"safety_check": {
    "is_safe_to_scan": true,
    "skip_reasons": [],
    "warnings": [],
    "scan_params": {
        "timing": "normal",
        "max_rate": null
    },
    "ip_validation": {
        "is_valid": true,
        "ip_type": "public",
        "is_scannable": true,
        "reason": null
    }
}
```

| Campo | Tipo | Descrizione |
|---|---|---|
| `is_safe_to_scan` | `bool` | `true` se il target può essere scansionato senza rischi |
| `skip_reasons` | `array[string]` | Motivi di blocco (se `is_safe_to_scan` è `false`) |
| `warnings` | `array[string]` | Avvertimenti non bloccanti |
| `scan_params` | `object` | Parametri di scansione consigliati dal safety validator |
| `scan_params.timing` | `string` | Timing raccomandato: `"normal"` o `"polite"` |
| `scan_params.max_rate` | `int\|null` | Rate limit raccomandato (pacchetti/sec) |
| `ip_validation` | `object` | Risultato della validazione IP |
| `ip_validation.is_valid` | `bool` | `true` se l'IP è formattato correttamente |
| `ip_validation.ip_type` | `string` | Classificazione IP: `public`, `private`, `loopback`, `link_local`, `reserved`, `multicast` |
| `ip_validation.is_scannable` | `bool` | `true` solo se `ip_type` è `"public"` |
| `ip_validation.reason` | `string\|null` | Motivo di non-scansionabilità (es. `"Private IP address"`) |

**Dove viene creato:** `tools/safety_validator_tool.py`, intero file (161 linee). Assegnato in `main.py` linea 697.

**Come:** `SafetyValidatorTool` combina due verifiche:
1. **IP Validation** — classifica l'IP (pubblico/privato/loopback ecc.) usando `ipaddress` stdlib
2. **Infrastructure-based decision** — calibra `timing` e `max_rate` se c'è WAF (`polite`, 25 req/s) o CDN/Cloud (`polite`, 50 req/s)

**Perché:** Impedisce di scansionare target fuori scope (IP privati, localhost) e adatta i parametri per non essere bloccati da WAF. È il gatekeeper della pipeline.

---

### 7.6 `scan_params_applied`

```json
"scan_params_applied": {
    "timing": "normal",
    "max_rate": null
}
```

| Campo | Tipo | Descrizione |
|---|---|---|
| `timing` | `string` | Timing effettivamente applicato: `"normal"` o `"polite"` |
| `max_rate` | `int\|null` | Rate limit effettivamente applicato |

**Dove viene creato:** `main.py`, linea 698, da `target_params[domain]` (linea 238: `target_params[domain] = safety.get('scan_params', {})`).

**Come:** Estratto direttamente dal `scan_params` restituito dal `SafetyValidatorTool`. Rappresenta i parametri **effettivamente applicati** a Nmap, Httpx, Nuclei e FFUF per questo specifico dominio.

**Perché:** Documenta i parametri reali usati per la scansione di ogni singolo target, che possono differire da quelli globali a causa dell'adattamento infrastrutturale (es. un target dietro WAF avrà timing polite anche se la scansione globale è "normal").

---

### 7.7 `subdomain_enum`

```json
"subdomain_enum": {
    "discovered_subdomains": [
        "mail.example.com",
        "vpn.example.com"
    ],
    "permutations": [
        "dev-mail.example.com",
        "staging.example.com"
    ],
    "method": "bruteforce",
    "seed_domain": "example.com",
    "wordlist_used": "wordlists/subdomains.txt"
}
```

Può anche essere `{}` se il dominio non è un seed originale della `target_list`.

| Campo | Tipo | Descrizione |
|---|---|---|
| `discovered_subdomains` | `array[string]` | Sottodomini trovati via puredns bruteforce |
| `permutations` | `array[string]` | Sottodomini trovati via AlterX + puredns resolve |
| `method` | `string` | Metodo usato: `"bruteforce"` |
| `seed_domain` | `string` | Dominio seed originale |
| `wordlist_used` | `string` | Wordlist usata per l'enumerazione |
| `error` | `string` | (opzionale) Messaggio di errore se la fase è fallita |

**Dove viene creato:**
- `tools/subdomain_enum_tool.py`, funzione `run()` (linee 62-202): Esecuzione di puredns bruteforce e/o resolve.
- `main.py`, funzione `run_subdomain_enumeration_phase()` (linee 75-180): Orchestrazione bruteforce + permutazioni + double check.
- `main.py`, linee 789-796: Assegnazione al JSON finale. **Solo i seed originali** hanno `subdomain_enum` popolato.

**Come:** La Fase 1 funziona in tre passaggi:
1. **Bruteforce** con `puredns` — testa tutte le combinazioni dalla wordlist
2. **Permutazioni** con `AlterX` — genera variazioni dei sottodomini trovati, poi li valida con `puredns resolve`
3. **Double Check** — ri-validazione DNS finale con `DnsManagerTool` per filtrare falsi positivi (anti-sinkholing)

**Perché:** Questa sezione documenta la "radice" della discovery, mostrando da dove provengono tutti i sottodomini aggiunti alla scansione.

---

### 7.8 `ports`

```json
"ports": [
    {
        "port": "443",
        "service": "https",
        "state": "open",
        "product": "",
        "version": ""
    },
    {
        "port": "80",
        "service": "http",
        "state": "open",
        "product": "nginx",
        "version": "1.21.6"
    }
]
```

Array di oggetti, uno per ogni porta rilevata.

| Campo | Tipo | Descrizione |
|---|---|---|
| `port` | `string` | Numero di porta |
| `service` | `string` | Nome del servizio rilevato da Nmap (es. `"http"`, `"https"`, `"domain"`, `"submission"`) |
| `state` | `string` | Stato: `"open"`, `"closed"`, `"filtered"`, `"open|filtered"` |
| `product` | `string` | Nome del prodotto software (se rilevato da `-sV`), es. `"nginx"` |
| `version` | `string` | Versione del prodotto (se rilevata) |

**Dove viene creato:**
- `tools/nmap_tool.py`, funzione `_scan_group()` (linee 115-141): Esecuzione di Nmap e raccolta risultati tramite `python-nmap`.
- `main.py`, linee 710-722: Parsing dei risultati NMap (struttura `tcp[port]`) e conversione in array piatto.

**Come:** Nmap scansiona gli **IP unici** (non i domini) per evitare ridondanza. I risultati vengono poi rimappati ai domini originali tramite `ip_to_domains`. Il profilo di scansione (`fast`, `accurate`, ecc.) influenza i flag di Nmap:
- `fast`: `-F --host-timeout 5m`
- `accurate`: `--top-ports 1000 -sV --version-intensity 9 -sC --host-timeout 15m`
- `comprehensive`: `-sS -sV -sC -sU -p U:53,... T:1-65535 --host-timeout 30m`
- `stealth`: `-sS --host-timeout 10m`

**Perché:** La lista porte è il ponte tra la fase di network recon e la fase web: solo le porte web (80, 443, 8080, 8443, o qualsiasi porta con servizio "http/https/ssl") vengono passate a Httpx.

---

### 7.9 `web_recon`

```json
"web_recon": {
    "mail.example.com:443": {
        "timestamp": "2026-03-09T15:48:58.157421909+01:00",
        "tls": { ... },
        "hash": {
            "body_sha256": "e3b0c44...",
            "header_sha256": "300f6050..."
        },
        "port": "443",
        "url": "https://mail.example.com:443",
        "input": "mail.example.com:443",
        "location": "https://mail.example.com/owa/",
        "scheme": "https",
        "webserver": "Microsoft-IIS/10.0",
        "content_type": "text/html",
        "method": "GET",
        "host": "mail.example.com",
        "host_ip": "212.25.183.115",
        "path": "/",
        "time": "76.246938ms",
        "a": ["212.25.183.115"],
        "cname": ["alias.example.com"],
        "tech": ["IIS:10.0", "Windows Server"],
        "words": 0,
        "lines": 0,
        "status_code": 302,
        "content_length": 0,
        "failed": false,
        "knowledgebase": { "PageType": "other", "pHash": 0 },
        "resolvers": ["127.0.0.53:53", "8.8.4.4:53"]
    }
}
```

Dizionario con chiave `dominio:porta`, contenente l'output diretto di HTTPX.

| Campo | Tipo | Descrizione |
|---|---|---|
| `timestamp` | `string` | Timestamp ISO 8601 della risposta |
| `tls` | `object` | (solo HTTPS) Dettagli del certificato TLS |
| `tls.tls_version` | `string` | Versione TLS (es. `"tls13"`) |
| `tls.cipher` | `string` | Cipher suite negoziata |
| `tls.not_before` / `not_after` | `string` | Validità del certificato |
| `tls.subject_cn` | `string` | Common Name del certificato |
| `tls.subject_an` | `array[string]` | Subject Alternative Names |
| `tls.issuer_cn` | `string` | Common Name dell'issuer |
| `tls.issuer_org` | `array[string]` | Organizzazione dell'issuer |
| `tls.fingerprint_hash` | `object` | Hash MD5/SHA1/SHA256 del certificato |
| `tls.wildcard_certificate` | `bool` | `true` se il cert è wildcard |
| `tls.sni` | `string` | Server Name Indication usato |
| `hash.body_sha256` | `string` | SHA256 del body HTTP |
| `hash.header_sha256` | `string` | SHA256 degli header HTTP |
| `port` | `string` | Porta della connessione |
| `url` | `string` | URL completo |
| `location` | `string` | Header `Location` (redirect) |
| `scheme` | `string` | `"http"` o `"https"` |
| `webserver` | `string` | Serverheader (es. `"nginx"`) |
| `content_type` | `string` | Header Content-Type |
| `host_ip` | `string` | IP risolto dell'host |
| `a` | `array[string]` | Record DNS A |
| `cname` | `array[string]` | Record DNS CNAME (se presenti) |
| `tech` | `array[string]` | Tecnologie rilevate (Wappalyzer-like) |
| `status_code` | `int` | HTTP status code |
| `content_length` | `int` | Lunghezza del body |
| `failed` | `bool` | `true` se la richiesta è fallita |
| `knowledgebase` | `object` | Classificazione interna httpx della pagina |

**Dove viene creato:**
- `tools/httpx_tool.py`, funzione `_scan_group()` (linee 116-164): Esecuzione di httpx con flag per output JSON completo.
- `main.py`, linee 737-740: Assegnazione al target per hostname.

**Come:** HTTPX viene invocato con flag per estrarre certificati TLS, hash body/header, tecnologie, DNS records, e status code. L'output JSON nativo di httpx viene parsato riga per riga e associato al target url originale.

**Perché:** Il web_recon è il cuore dell'analisi web: fornisce fingerprinting tecnologico, informazioni TLS, redirect chain, e identifica quali target sono effettivamente "vivi". I dati `tech` vengono riutilizzati dalla Fase 5 per la content discovery context-aware.

---

### 7.10 `spidering`

```json
"spidering": {
    "mail.example.com:443": {
        "base_domain": "mail.example.com",
        "endpoints_count": 18,
        "js_files_count": 0,
        "js_files": [],
        "hidden_libraries_count": 0,
        "validated_endpoints": [],
        "validated_endpoints_count": 0
    }
}
```

Dizionario con chiave `dominio:porta`.

| Campo | Tipo | Descrizione |
|---|---|---|
| `base_domain` | `string` | Hostname del target |
| `endpoints_count` | `int` | Numero totale di endpoint scoperti dal crawler (pre-validazione) |
| `js_files_count` | `int` | Numero di file JS custom trovati (escluse le librerie note) |
| `js_files` | `array[string]` | URL dei file JS custom **validati** (rispondono 2xx/3xx) |
| `hidden_libraries_count` | `int` | Numero di librerie JS note nascoste dal report (jQuery, React, ecc.) |
| `validated_endpoints` | `array[string]` | Endpoint **validati** che rispondono effettivamente (2xx/3xx) |
| `validated_endpoints_count` | `int` | Conteggio endpoint validati |

> **Nota:** I campi `endpoints` (lista grezza), `paths_wordlist` e `raw_js_files` vengono rimossi dal JSON finale per ridurre il noise (linee 756-758 di `main.py`).

**Dove viene creato:**
- `tools/spider_tool.py`, funzione `_execute_katana()` (linee 98-218): Esecuzione di Katana (ProjectDiscovery) con JS crawling e form filling.
- `main.py`, linee 347-394 (`run_content_discovery_phase`): Post-processing con batch validation via httpx e filtraggio librerie JS note.
- `main.py`, linee 751-760: Assegnazione al JSON finale con rimozione dei campi grezzi.

**Come:** Katana spidera il sito seguendo link, form, e file JS. Il tool classifica i JS in "custom" vs "librerie note" (jQuery, React, Angular ecc.) usando una combinazione di regex e CDN domain matching. Tutti gli endpoint e JS vengono poi batch-validati via httpx per separare i link vivi dai dead link.

**Perché:** Lo spidering alimenta due fasi successive:
1. I **JS custom** vengono passati alla JS Analysis (jsluice)
2. Gli **endpoint/path** diventano una wordlist dinamica per FFUF

---

### 7.11 `js_analysis`

```json
"js_analysis": {
    "endpoints": [
        "/api/v1/users",
        "/api/v1/auth/login?redirect=/"
    ],
    "total_extracted_endpoints": 2
}
```

oppure `{}` se non sono stati trovati file JS custom.

| Campo | Tipo | Descrizione |
|---|---|---|
| `endpoints` | `array[string]` | Path/URL estratti dai file JS e **validati** come vivi |
| `total_extracted_endpoints` | `int` | Conteggio degli endpoint estratti e validati |

**Dove viene creato:**
- `tools/js_analyzer_tool.py`: Esecuzione di `jsluice` per parsare i file JS ed estrarre URL/API.
- `main.py`, linee 396-445 (`run_content_discovery_phase`): Orchestrazione, batch validation, normalizzazione.
- `main.py`, linee 762-765: Assegnazione al target.

**Come:** I file JS custom trovati dallo spider vengono passati a `jsluice` che li analizza staticamente per estrarre URL, endpoint API, e secret. I risultati vengono poi batch-validati con httpx e le path valide vengono aggiunte sia al report che alla wordlist dinamica per FFUF.

**Perché:** I file JavaScript contengono spesso endpoint API non documentati, configurazioni backend, e a volte credenziali hardcoded. L'analisi statica JS è una tecnica fondamentale nel modern web recon.

---

### 7.12 `advanced_fingerprint`

```json
"advanced_fingerprint": [
    {
        "id": "microsoft-iis-version",
        "name": "Microsoft IIS version detect",
        "severity": "info",
        "matched_at": "https://mail.example.com:443",
        "description": "Some Microsoft IIS servers have the version...",
        "extracted_results": ["Microsoft-IIS/10.0"],
        "ip": "212.25.183.115",
        "tags": ["tech", "microsoft", "iis", "discovery"]
    },
    {
        "id": "tech-detect",
        "name": "Wappalyzer Technology Detection",
        "severity": "info",
        "matched_at": "https://mail.example.com:443",
        "description": "",
        "matcher_name": "ms-iis",
        "ip": "212.25.183.115",
        "tags": ["tech", "discovery"]
    }
]
```

Array di oggetti, uno per ogni finding di Nuclei.

| Campo | Tipo | Descrizione |
|---|---|---|
| `id` | `string` | ID del template Nuclei (es. `"microsoft-iis-version"`) |
| `name` | `string` | Nome leggibile del check |
| `severity` | `string` | Severità: `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"` |
| `matched_at` | `string` | URL esatto dove il template ha matchato |
| `description` | `string` | Descrizione del finding |
| `extracted_results` | `array[string]` | (opzionale) Risultati estratti via regex (es. versione software) |
| `matcher_name` | `string` | (opzionale) Nome del matcher specifico che ha triggerato |
| `ip` | `string` | (opzionale) IP del target |
| `tags` | `array[string]` | (opzionale) Tag del template (es. `["tech", "discovery"]`) |
| `error` | `string` | (opzionale) Messaggio di errore se Nuclei ha fallito |

**Dove viene creato:**
- `tools/nuclei_tool.py`, funzione `_scan_group()` (linee 133-247): Parsing riga per riga dell'output JSON di Nuclei.
- `main.py`, linee 742-749: Assegnazione al target corretto per hostname.

**Come:** Nuclei viene eseguito con template di fingerprinting e detection (tag `tech` e profili specifici). L'output JSON nativo viene semplificato estraendo solo i campi salienti (`id`, `name`, `severity`, `matched_at`, `description`, `extracted_results`, `matcher_name`, `ip`, `tags`). Il matching target è a cascata: match esatto → host-based → substring.

**Perché:** Il fingerprinting avanzato va oltre httpx, rilevando versioni software esatte, framework specifici, pannelli admin, WAF, e potenziali vulnerabilità classificate per severità.

> **Nota:** Se il flag `--skip-nuclei` è attivo o `skip_nuclei: true` nel JSON di input, questo array sarà vuoto `[]`.

---

### 7.13 `content_discovery`

```json
"content_discovery": [
    {
        "endpoint": "https://mail.example.com/owa/",
        "status": 301,
        "length": 0,
        "words": 0,
        "lines": 0,
        "content_type": "text/html"
    }
]
```

Array di oggetti, uno per ogni path scoperta da FFUF.

| Campo | Tipo | Descrizione |
|---|---|---|
| `endpoint` | `string` | URL completo della risorsa scoperta |
| `status` | `int` | HTTP status code della risposta |
| `length` | `int` | Content-Length in bytes |
| `words` | `int` | Numero di parole nella risposta |
| `lines` | `int` | Numero di righe nella risposta |
| `content_type` | `string` | Header Content-Type |
| `error` | `string` | (opzionale) Messaggio di errore se FFUF ha fallito/timeout |

**Dove viene creato:**
- `tools/content_discovery_tool.py`, funzione `_do_ffuf_run()` (linee 295-393): Esecuzione di FFUF e parsing dell'output JSON.
- `main.py`, linee 767-774: Assegnazione al target.

**Come:** FFUF è il fuzzer che testa directory e file. Il tool opera in modalità **context-aware**:
1. Determina le estensioni da testare in base alle technologie rilevate da httpx (es. PHP → `.php, .txt, .bak`)
2. Seleziona wordlist specifiche per tecnologia (es. WordPress → `wordpress.txt`)
3. Integra la wordlist dinamica dai risultati dello spidering e JS analysis
4. Esegue fino a 3 run separate: wordlist dinamica, wordlist base + estensioni, wordlist tech-specific
5. Auto-calibrazione (`-ac`) per filtrare wildcard/falsi positivi

**Perché:** La content discovery rivela file e directory non linkati, backup, pannelli admin, configurazioni esposte, e altre risorse nascote non raggiungibili tramite spidering.

> **Nota:** Se il flag `--skip-content-discovery` è attivo o `skip_content_discovery: true` nel JSON di input, questo array sarà vuoto `[]`.

---

### 7.14 `vhost_enum`

```json
"vhost_enum": {
    "mail.example.com:443": {
        "domain": "mail.example.com",
        "port": "443",
        "discovered_vhosts": [
            {
                "vhost": "hidden.example.com",
                "status_code": 200,
                "content_length": 12345,
                "content_words": 150,
                "content_lines": 50,
                "url": "https://[185.10.20.30]:443/",
                "redirect_location": "",
                "target_ip_used": "185.10.20.30",
                "bypassed_via": "Host"
            }
        ],
        "count": 1,
        "ips_scanned": ["212.25.183.115"]
    }
}
```

Dizionario con chiave `dominio:porta`.

| Campo | Tipo | Descrizione |
|---|---|---|
| `domain` | `string` | Dominio target |
| `port` | `string` | Porta scansionata |
| `discovered_vhosts` | `array[object]` | Virtual host nascosti scoperti |
| `discovered_vhosts[].vhost` | `string` | FQDN del vhost scoperto (es. `"hidden.example.com"`) |
| `discovered_vhosts[].status_code` | `int` | HTTP status code della risposta |
| `discovered_vhosts[].content_length` | `int` | Content-Length |
| `discovered_vhosts[].content_words` | `int` | Parole nella risposta |
| `discovered_vhosts[].content_lines` | `int` | Righe nella risposta |
| `discovered_vhosts[].url` | `string` | URL diretto all'IP usato |
| `discovered_vhosts[].redirect_location` | `string` | Header Location (se redirect) |
| `discovered_vhosts[].target_ip_used` | `string` | IP bersaglio della richiesta |
| `discovered_vhosts[].bypassed_via` | `string` | Header usato per il bypass (`"Host"`, `"X-Forwarded-Host"`, ecc.) |
| `count` | `int` | Conteggio vhost scoperti |
| `ips_scanned` | `array[string]` | Lista IP testati (include origin IP se trovati) |

**Dove viene creato:**
- `tools/vhost_enum_tool.py`, funzioni `_scan_ip_group()` (linee 219-309) e `_parse_ffuf_output()` (linee 311-352).
- `main.py`, linee 776-780: Assegnazione al target.

**Come:** FFUF viene usato per fuzzing dell'header `Host:` (e opzionalmente `X-Forwarded-Host`, `X-Host`, `Forwarded`) contro gli IP del target. La tecnica scopre virtual host nascosti ospitati sullo stesso server ma non esposti pubblicamente nel DNS. Il tool testa sia gli IP diretti che gli origin IP scoperti dalla Fase 2.

**Perché:** Virtual hosting è ubiquo: un singolo IP spesso ospita multiple applicazioni web. Scoprire i vhost nascosti espande significativamente la superficie di attacco.

---

### 7.15 `ip_rotation`

```json
"ip_rotation": {
    "status": "static",
    "observations": 68,
    "unique_ips": ["212.25.183.115"],
    "changes_detected": 0,
    "monitoring_duration_seconds": 671.0
}
```

| Campo | Tipo | Descrizione |
|---|---|---|
| `status` | `string` | Stato rilevato: `"static"` (IP fisso), `"rotating"` (IP cambia), `"insufficient_data"` (< 2 osservazioni) |
| `observations` | `int` | Numero totale di risoluzioni DNS effettuate durante il monitoraggio |
| `unique_ips` | `array[string]` | Set unico di IP osservati durante tutto il periodo |
| `changes_detected` | `int` | Numero di volte che l'IP è cambiato tra due osservazioni consecutive |
| `monitoring_duration_seconds` | `float` | Durata effettiva del monitoraggio in secondi |

**Dove viene creato:**
- `tools/ip_rotation_tool.py`, funzione `get_results()` (linee 176-227): Analisi della cronologia DNS raccolta dal thread in background.
- `main.py`, linee 649-651 (start), 677-678 (stop e raccolta risultati), 782-785 (assegnazione).

**Come:** `IPRotationTool` crea un **thread in background** che esegue risoluzioni DNS periodiche (configurabili: default ogni 10s per almeno 30s). Il thread gira **in parallelo** con le fasi 3-6 della pipeline, monitorando se gli IP cambiano nel tempo. Alla fine, analizza la cronologia per determinare se il dominio usa:
- **IP statico** — stesso IP per tutta la durata
- **IP rotante** — IP diversi osservati (es. load balancer, GeoDNS)

**Perché:** La rotazione IP è un indicatore chiave:
- Segnala l'uso di load balancer, CDN, o GeoDNS
- Impatta le strategie di bypass (un IP trovato potrebbe non essere più valido)
- Influenza la pianificazione delle scansioni ripetute

---

## Diagramma di flusso dati

```
Input JSON
    │
    ▼
┌─────────────────────────────────┐
│   Fase 1: Subdomain Enumeration │ ──► subdomain_enum
│   (puredns + AlterX + DNS)      │
└────────────┬────────────────────┘
             │ lista domini espansa
             ▼
┌─────────────────────────────────┐
│ Fase 2: Infrastructure Analysis │ ──► infrastructure
│ (cdncheck + OriginIP + Safety)  │     origin_ip_bypass
│                                 │     safety_check
│                                 │     scan_params_applied
└────────────┬────────────────────┘
             │ safe_targets + ip_map
             ▼
┌─────────────────────────────────┐     ┌─────────────────────────┐
│  Fase 3: Port Scanning (Nmap)   │ ──► │ ports                   │
│                                 │     └─────────────────────────┘
└────────────┬────────────────────┘
             │ web_targets (dominio:porta)
             ▼
┌─────────────────────────────────┐
│ Fase 4: Web Recon (Httpx/Nuclei)│ ──► web_recon
│                                 │     advanced_fingerprint
└────────────┬────────────────────┘
             │ alive_web_targets
             ▼
┌─────────────────────────────────┐
│ Fase 5: Content Discovery       │ ──► spidering
│ (Katana + Jsluice + FFUF)       │     js_analysis
│                                 │     content_discovery
└────────────┬────────────────────┘
             ▼
┌─────────────────────────────────┐
│ Fase 6: VHost Enumeration       │ ──► vhost_enum
│ (FFUF Host Header fuzzing)      │
└─────────────────────────────────┘

   ┌────────────────────────────────┐
   │ Background: IP Rotation Monitor│ ──► ip_rotation
   │ (thread parallel alle fasi 3-6)│
   └────────────────────────────────┘
```
