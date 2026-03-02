#!/usr/bin/env python3
"""
Benchmark ASM-Grade: pureDNS vs shuffleDNS (v6)

Struttura a 2 fasi:
  FASE 1 - Cold Start Bruteforce (ordine random, cache fredde)
  FASE 2 - Consistenza (run alternati con pausa tra i round)

Caratteristiche:
  - Wildcard detection OFF su entrambi (confronto puro)
  - Threads shuffleDNS auto-calcolati (resolver × 5)
  - Ordine di esecuzione randomizzato
  - FP calcolati come TASSO percentuale
  - Domini comuni + esclusivi validati con DNS trusted
  - Report esplicito con vincitore per ogni criterio
"""

import subprocess
import shutil
import time
import argparse
import sys
import os
import random
import statistics
import dns.resolver
import dns.exception
import concurrent.futures
from datetime import datetime

# ─────────────────────────────────────────────
# Colori ANSI
# ─────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"
MAGENTA = "\033[95m"

def h(text):    return f"{BOLD}{text}{RESET}"
def ok(text):   return f"{GREEN}✔{RESET} {text}"
def warn(text): return f"{YELLOW}⚠{RESET}  {text}"
def err(text):  return f"{RED}✘{RESET} {text}"
def info(text): return f"{CYAN}→{RESET} {text}"
def phase_hdr(n, title): return f"\n{MAGENTA}{'━'*60}\n  FASE {n}: {title}\n{'━'*60}{RESET}"

def sep(char="─", width=60):
    print(f"{DIM}{char * width}{RESET}")

# ─────────────────────────────────────────────
# Dependency check
# ─────────────────────────────────────────────
def check_deps():
    missing = []
    for tool in ["puredns", "shuffledns", "massdns"]:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        print(err(f"Tool mancanti: {', '.join(missing)}"))
        sys.exit(1)
    print(ok("Dipendenze: puredns, shuffledns, massdns"))

# ─────────────────────────────────────────────
# Runners
# ─────────────────────────────────────────────
MASSDNS_PATH = shutil.which("massdns") or "massdns"

def run_puredns_bruteforce(target, wordlist, resolvers, rate, output_file):
    cmd = [
        "puredns", "bruteforce", wordlist, target,
        "-r", resolvers, "-l", str(rate),
        "--skip-wildcard-filter", "--skip-validation", "--quiet",
        "-w", output_file
    ]
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    return time.time() - start, result.returncode, result.stderr.strip()

def run_shuffledns_bruteforce(target, wordlist, resolvers, threads, output_file):
    cmd = [
        "shuffledns", "-d", target, "-w", wordlist,
        "-r", resolvers, "-m", MASSDNS_PATH,
        "-mode", "bruteforce", "-t", str(threads),
        "-o", output_file, "-silent"
    ]
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    return time.time() - start, result.returncode, result.stderr.strip()

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def load_results(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath) as f:
        return set(line.strip() for line in f if line.strip())

def clean_files(*files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def count_lines(filepath):
    with open(filepath) as f:
        return sum(1 for _ in f)

# ─────────────────────────────────────────────
# Validazione con DNS Trusted
# ─────────────────────────────────────────────
TRUSTED_DNS = ['1.1.1.1', '8.8.8.8', '9.9.9.9']

def validate_domain(domain):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = TRUSTED_DNS
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        resolver.resolve(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    except dns.resolver.NoNameservers:
        return False
    except dns.exception.Timeout:
        return None
    except Exception:
        return None

def validate_domains(domains):
    if not domains:
        return set(), set(), set()
    valid, invalid, uncertain = set(), set(), set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {executor.submit(validate_domain, d): d for d in domains}
        for future in concurrent.futures.as_completed(future_map):
            d = future_map[future]
            result = future.result()
            if result is True:
                valid.add(d)
            elif result is False:
                invalid.add(d)
            else:
                uncertain.add(d)
    return valid, invalid, uncertain

# ─────────────────────────────────────────────
# Scoring: gestisce pareggi correttamente
# ─────────────────────────────────────────────
def score_criterion(pd_val, sd_val, higher_is_better=True):
    """
    Confronta due valori e ritorna il punteggio per ciascuno.
    Ritorna (pd_score, sd_score): (1,0) o (0,1) o (0.5, 0.5) in caso di pareggio.
    """
    if pd_val == sd_val:
        return 0.5, 0.5
    if higher_is_better:
        return (1, 0) if pd_val > sd_val else (0, 1)
    else:
        return (1, 0) if pd_val < sd_val else (0, 1)

def winner_label(pd_val, sd_val, higher_is_better=True):
    """Ritorna il nome del vincitore e il colore."""
    if pd_val == sd_val:
        return f"{YELLOW}PAREGGIO{RESET}"
    if higher_is_better:
        return f"{GREEN}pureDNS{RESET}" if pd_val > sd_val else f"{GREEN}shuffleDNS{RESET}"
    else:
        return f"{GREEN}pureDNS{RESET}" if pd_val < sd_val else f"{GREEN}shuffleDNS{RESET}"

# ─────────────────────────────────────────────
# FASE 1: Cold Start Bruteforce
# ─────────────────────────────────────────────
def phase1_cold_bruteforce(target, wordlist, resolvers, rate, sd_threads):
    print(phase_hdr(1, "COLD START BRUTEFORCE"))
    print(info(f"Target: {target} | Wordlist: {count_lines(wordlist)} voci"))
    print(info(f"pureDNS: rate={rate}/s, --skip-wildcard-filter"))
    print(info(f"shuffleDNS: threads={sd_threads}, wildcard detection OFF (default)"))
    print()

    pd_out = f"/tmp/bench_p1_pd_{target}.txt"
    sd_out = f"/tmp/bench_p1_sd_{target}.txt"
    clean_files(pd_out, sd_out)

    # Scelta casuale di chi parte primo
    pd_first = random.choice([True, False])
    first_label = "pureDNS" if pd_first else "shuffleDNS"
    print(info(f"Ordine: {first_label} primo (scelto casualmente)"))
    print()

    if pd_first:
        print(info(f"pureDNS  (rate={rate}/s)..."), end=" ", flush=True)
        pd_time, _, pd_err = run_puredns_bruteforce(target, wordlist, resolvers, rate, pd_out)
        pd_results = load_results(pd_out)
        print(f"{pd_time:.1f}s → {len(pd_results)} risultati")

        print(info("Pausa 60s per decadimento cache resolver..."), flush=True)
        time.sleep(60)

        print(info(f"shuffleDNS (threads={sd_threads})..."), end=" ", flush=True)
        sd_time, _, sd_err = run_shuffledns_bruteforce(target, wordlist, resolvers, sd_threads, sd_out)
        sd_results = load_results(sd_out)
        print(f"{sd_time:.1f}s → {len(sd_results)} risultati")
    else:
        print(info(f"shuffleDNS (threads={sd_threads})..."), end=" ", flush=True)
        sd_time, _, sd_err = run_shuffledns_bruteforce(target, wordlist, resolvers, sd_threads, sd_out)
        sd_results = load_results(sd_out)
        print(f"{sd_time:.1f}s → {len(sd_results)} risultati")

        print(info("Pausa 60s per decadimento cache resolver..."), flush=True)
        time.sleep(60)

        print(info(f"pureDNS  (rate={rate}/s)..."), end=" ", flush=True)
        pd_time, _, pd_err = run_puredns_bruteforce(target, wordlist, resolvers, rate, pd_out)
        pd_results = load_results(pd_out)
        print(f"{pd_time:.1f}s → {len(pd_results)} risultati")

    # Analisi
    common = pd_results & sd_results
    only_pd = pd_results - sd_results
    only_sd = sd_results - pd_results

    # Validazione risultati "in comune" (non assumere che siano tutti reali)
    print(info(f"Validazione DNS trusted: {len(common)} comuni + {len(only_pd)} esclusivi pureDNS + {len(only_sd)} esclusivi shuffleDNS"))
    print(info(f"  Comuni ({len(common)})..."), end=" ", flush=True)
    common_valid, common_fp, common_unc = validate_domains(common)
    print(f"{len(common_valid)} ✔  {len(common_fp)} ✘  {len(common_unc)} ?")

    # Validazione esclusivi
    print(info(f"  Solo pureDNS ({len(only_pd)})..."), end=" ", flush=True)
    pd_valid, pd_fp, pd_unc = validate_domains(only_pd)
    print(f"{len(pd_valid)} ✔  {len(pd_fp)} ✘  {len(pd_unc)} ?")

    print(info(f"  Solo shuffleDNS ({len(only_sd)})..."), end=" ", flush=True)
    sd_valid, sd_fp, sd_unc = validate_domains(only_sd)
    print(f"{len(sd_valid)} ✔  {len(sd_fp)} ✘  {len(sd_unc)} ?")

    total_validated = len(common) + len(only_pd) + len(only_sd)
    total_valid = len(common_valid) + len(pd_valid) + len(sd_valid)
    total_fp = len(common_fp) + len(pd_fp) + len(sd_fp)
    print(info(f"  Totale: {total_validated} validati → {total_valid} validi, {total_fp} FP"))

    if pd_err:
        print(f"  {DIM}pureDNS stderr: {pd_err[:200]}{RESET}")
    if sd_err:
        print(f"  {DIM}shuffleDNS stderr: {sd_err[:200]}{RESET}")

    return {
        "pd_time": pd_time, "sd_time": sd_time,
        "pd_results": pd_results, "sd_results": sd_results,
        "common_valid": common_valid, "common_fp": common_fp, "common_unc": common_unc,
        "only_pd": only_pd, "only_sd": only_sd,
        "pd_valid": pd_valid, "pd_fp": pd_fp, "pd_unc": pd_unc,
        "sd_valid": sd_valid, "sd_fp": sd_fp, "sd_unc": sd_unc,
    }


# ─────────────────────────────────────────────
# FASE 2: Consistenza
# ─────────────────────────────────────────────
def phase2_consistency(target, wordlist, resolvers, rate, sd_threads, rounds, pause):
    print(phase_hdr(2, f"CONSISTENZA ({rounds} run, pausa {pause}s)"))
    print(info("Misura la stabilità dei risultati tra esecuzioni indipendenti"))
    print()

    pd_counts, sd_counts = [], []
    pd_times, sd_times = [], []

    for i in range(rounds):
        run_num = i + 1
        print(f"  {h(f'Run {run_num}/{rounds}')}")

        pd_out = f"/tmp/bench_p2_pd_{target}_r{run_num}.txt"
        sd_out = f"/tmp/bench_p2_sd_{target}_r{run_num}.txt"
        clean_files(pd_out, sd_out)

        if run_num % 2 == 1:
            print(info("pureDNS..."), end=" ", flush=True)
            pd_t, _, _ = run_puredns_bruteforce(target, wordlist, resolvers, rate, pd_out)
            pd_r = load_results(pd_out)
            print(f"{pd_t:.1f}s → {len(pd_r)}")
            print(info("shuffleDNS..."), end=" ", flush=True)
            sd_t, _, _ = run_shuffledns_bruteforce(target, wordlist, resolvers, sd_threads, sd_out)
            sd_r = load_results(sd_out)
            print(f"{sd_t:.1f}s → {len(sd_r)}")
        else:
            print(info("shuffleDNS..."), end=" ", flush=True)
            sd_t, _, _ = run_shuffledns_bruteforce(target, wordlist, resolvers, sd_threads, sd_out)
            sd_r = load_results(sd_out)
            print(f"{sd_t:.1f}s → {len(sd_r)}")
            print(info("pureDNS..."), end=" ", flush=True)
            pd_t, _, _ = run_puredns_bruteforce(target, wordlist, resolvers, rate, pd_out)
            pd_r = load_results(pd_out)
            print(f"{pd_t:.1f}s → {len(pd_r)}")

        pd_counts.append(len(pd_r))
        sd_counts.append(len(sd_r))
        pd_times.append(pd_t)
        sd_times.append(sd_t)

        if i < rounds - 1:
            print(info(f"Pausa {pause}s..."), flush=True)
            time.sleep(pause)

    return {
        "pd_counts": pd_counts, "sd_counts": sd_counts,
        "pd_times": pd_times, "sd_times": sd_times,
    }

# ─────────────────────────────────────────────
# Report finale
# ─────────────────────────────────────────────
def print_final_report(target, wordlist_lines, p1, p2):
    print(f"\n{'═'*60}")
    print(f"  {h('REPORT FINALE')}  —  target: {CYAN}{target}{RESET}")
    print(f"  {DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | wordlist: {wordlist_lines}{RESET}")
    print(f"{'═'*60}")

    # Accumula risultati per il verdetto finale
    verdict_rows = []  # (criterio, pd_val_str, sd_val_str, vincitore, pd_pts, sd_pts)

    # ══════════════════════════════════════════
    # FASE 1: Cold Start
    # ══════════════════════════════════════════
    print(f"\n{h('  FASE 1: COLD START BRUTEFORCE')}")
    sep()

    wl = wordlist_lines
    pd_qps = wl / p1["pd_time"] if p1["pd_time"] > 0 else 0
    sd_qps = wl / p1["sd_time"] if p1["sd_time"] > 0 else 0

    # --- Velocità ---
    print(f"\n  {h('Velocità')}")
    print(f"    pureDNS     {p1['pd_time']:6.1f}s   ~{pd_qps:5.0f} query/s")
    print(f"    shuffleDNS  {p1['sd_time']:6.1f}s   ~{sd_qps:5.0f} query/s")
    ps, ss = score_criterion(p1["pd_time"], p1["sd_time"], higher_is_better=False)
    wlbl = "pureDNS" if ps > ss else ("shuffleDNS" if ss > ps else "PAREGGIO")
    verdict_rows.append(("Velocità cold", f"{p1['pd_time']:.1f}s", f"{p1['sd_time']:.1f}s", wlbl, ps, ss))
    print(f"    Vincitore: {winner_label(p1['pd_time'], p1['sd_time'], higher_is_better=False)}")

    # --- Copertura ---
    print(f"\n  {h('Copertura (domini confermati validi)')}")
    pd_confirmed = len(p1["common_valid"]) + len(p1["pd_valid"])
    sd_confirmed = len(p1["common_valid"]) + len(p1["sd_valid"])
    print(f"    pureDNS     {len(p1['pd_results']):4} trovati → {pd_confirmed:4} confermati validi")
    print(f"    shuffleDNS  {len(p1['sd_results']):4} trovati → {sd_confirmed:4} confermati validi")
    print(f"    {DIM}Comuni validati: {len(p1['common_valid'])} | Comuni falsi pos.: {len(p1['common_fp'])} | Comuni incerti: {len(p1['common_unc'])}{RESET}")
    ps, ss = score_criterion(pd_confirmed, sd_confirmed, higher_is_better=True)
    wlbl = "pureDNS" if ps > ss else ("shuffleDNS" if ss > ps else "PAREGGIO")
    verdict_rows.append(("Copertura valida", str(pd_confirmed), str(sd_confirmed), wlbl, ps, ss))
    print(f"    Vincitore: {winner_label(pd_confirmed, sd_confirmed, higher_is_better=True)}")

    # --- Falsi Positivi (TASSO) ---
    print(f"\n  {h('Tasso di falsi positivi')}")
    pd_all_fp = len(p1["pd_fp"]) + len(p1["common_fp"])
    sd_all_fp = len(p1["sd_fp"]) + len(p1["common_fp"])
    pd_fp_rate = (pd_all_fp / len(p1["pd_results"]) * 100) if len(p1["pd_results"]) > 0 else 0
    sd_fp_rate = (sd_all_fp / len(p1["sd_results"]) * 100) if len(p1["sd_results"]) > 0 else 0
    print(f"    pureDNS     {len(p1['pd_fp']):3} FP esclusivi  →  tasso: {pd_fp_rate:5.1f}%")
    print(f"    shuffleDNS  {len(p1['sd_fp']):3} FP esclusivi  →  tasso: {sd_fp_rate:5.1f}%")
    print(f"    {DIM}FP condivisi (entrambi sbagliano): {len(p1['common_fp'])}{RESET}")
    ps, ss = score_criterion(pd_fp_rate, sd_fp_rate, higher_is_better=False)
    wlbl = "pureDNS" if ps > ss else ("shuffleDNS" if ss > ps else "PAREGGIO")
    verdict_rows.append(("Falsi positivi", f"{pd_fp_rate:.1f}%", f"{sd_fp_rate:.1f}%", wlbl, ps, ss))
    print(f"    Vincitore: {winner_label(pd_fp_rate, sd_fp_rate, higher_is_better=False)}")

    # Dettaglio esclusivi
    if p1["only_pd"]:
        print(f"\n  {DIM}Solo pureDNS ({len(p1['only_pd'])}): {len(p1['pd_valid'])} ✔ | {len(p1['pd_fp'])} ✘ | {len(p1['pd_unc'])} ?{RESET}")
        for d in sorted(p1["pd_valid"])[:10]:
            print(f"    {GREEN}✔{RESET} {d}")
        for d in sorted(p1["pd_fp"])[:10]:
            print(f"    {RED}✘{RESET} {d}")
        shown = min(len(p1["pd_valid"]), 10) + min(len(p1["pd_fp"]), 10)
        remaining = len(p1["only_pd"]) - shown
        if remaining > 0:
            print(f"    {DIM}... e altri {remaining}{RESET}")
    if p1["only_sd"]:
        print(f"\n  {DIM}Solo shuffleDNS ({len(p1['only_sd'])}): {len(p1['sd_valid'])} ✔ | {len(p1['sd_fp'])} ✘ | {len(p1['sd_unc'])} ?{RESET}")
        for d in sorted(p1["sd_valid"])[:10]:
            print(f"    {GREEN}✔{RESET} {d}")
        for d in sorted(p1["sd_fp"])[:10]:
            print(f"    {RED}✘{RESET} {d}")
        shown = min(len(p1["sd_valid"]), 10) + min(len(p1["sd_fp"]), 10)
        remaining = len(p1["only_sd"]) - shown
        if remaining > 0:
            print(f"    {DIM}... e altri {remaining}{RESET}")

    # ══════════════════════════════════════════
    # FASE 2: Consistenza
    # ══════════════════════════════════════════
    print(f"\n{h('  FASE 2: CONSISTENZA')}")
    sep()

    pd_avg = statistics.mean(p2["pd_counts"])
    sd_avg = statistics.mean(p2["sd_counts"])
    pd_tavg = statistics.mean(p2["pd_times"])
    sd_tavg = statistics.mean(p2["sd_times"])

    pd_stdev = statistics.stdev(p2["pd_counts"]) if len(p2["pd_counts"]) > 1 else 0
    sd_stdev = statistics.stdev(p2["sd_counts"]) if len(p2["sd_counts"]) > 1 else 0
    pd_tstdev = statistics.stdev(p2["pd_times"]) if len(p2["pd_times"]) > 1 else 0
    sd_tstdev = statistics.stdev(p2["sd_times"]) if len(p2["sd_times"]) > 1 else 0

    pd_cv = (pd_stdev / pd_avg * 100) if pd_avg > 0 else 0
    sd_cv = (sd_stdev / sd_avg * 100) if sd_avg > 0 else 0

    print(f"\n  {'':14} {'Media':>7}  {'σ':>5}  {'CV':>6}  {'Tempo medio':>12}  {'σ':>5}")
    print(f"  {'pureDNS':14} {pd_avg:>6.0f}  {pd_stdev:>5.1f}  {pd_cv:>5.1f}%  {pd_tavg:>10.1f}s  {pd_tstdev:>5.1f}")
    print(f"  {'shuffleDNS':14} {sd_avg:>6.0f}  {sd_stdev:>5.1f}  {sd_cv:>5.1f}%  {sd_tavg:>10.1f}s  {sd_tstdev:>5.1f}")

    print(f"\n  {DIM}Dettaglio run:{RESET}")
    for i in range(len(p2["pd_counts"])):
        first = "pureDNS" if (i+1) % 2 == 1 else "shuffleDNS"
        print(f"    Run {i+1}: puredns={p2['pd_counts'][i]} ({p2['pd_times'][i]:.1f}s) | "
              f"shuffledns={p2['sd_counts'][i]} ({p2['sd_times'][i]:.1f}s)  [{first} primo]")

    ps, ss = score_criterion(pd_cv, sd_cv, higher_is_better=False)
    wlbl = "pureDNS" if ps > ss else ("shuffleDNS" if ss > ps else "PAREGGIO")
    verdict_rows.append(("Stabilità (CV)", f"{pd_cv:.1f}%", f"{sd_cv:.1f}%", wlbl, ps, ss))
    print(f"\n  Stabilità (CV più basso = meglio): pureDNS {pd_cv:.1f}% | shuffleDNS {sd_cv:.1f}%")
    print(f"  Vincitore: {winner_label(pd_cv, sd_cv, higher_is_better=False)}")

    # ══════════════════════════════════════════
    # VERDETTO FINALE
    # ══════════════════════════════════════════
    pd_total = sum(r[4] for r in verdict_rows)
    sd_total = sum(r[5] for r in verdict_rows)
    total = pd_total + sd_total

    print(f"\n{'═'*60}")
    print(f"  {h('VERDETTO FINALE')}")
    print(f"{'═'*60}")

    # Tabella riepilogo con vincitore e valori per ogni criterio
    print(f"\n  {'Criterio':<20} {'pureDNS':>10} {'shuffleDNS':>12} {'Vincitore':>14}")
    sep()
    for name, pd_val, sd_val, winner, _, _ in verdict_rows:
        if winner == "pureDNS":
            winner_colored = f"{GREEN}pureDNS{RESET}"
        elif winner == "shuffleDNS":
            winner_colored = f"{GREEN}shuffleDNS{RESET}"
        else:
            winner_colored = f"{YELLOW}PAREGGIO{RESET}"
        print(f"  {name:<20} {pd_val:>10} {sd_val:>12}   {winner_colored}")

    sep()
    print(f"\n  {h('pureDNS')}     {pd_total:.1f} / {total:.1f}")
    print(f"  {h('shuffleDNS')}  {sd_total:.1f} / {total:.1f}")

    sep("═")
    if pd_total > sd_total:
        print(f"  {BOLD}{GREEN}★ CONSIGLIATO: pureDNS  ({pd_total:.1f}/{total:.1f}){RESET}")
    elif sd_total > pd_total:
        print(f"  {BOLD}{GREEN}★ CONSIGLIATO: shuffleDNS  ({sd_total:.1f}/{total:.1f}){RESET}")
    else:
        print(f"  {BOLD}{YELLOW}★ PAREGGIO PERFETTO  ({pd_total:.1f}/{total:.1f}){RESET}")
    print(f"{'═'*60}\n")

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Benchmark ASM-Grade: pureDNS vs shuffleDNS (v6)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempio:
  python3 dns_benchmark.py --target github.com --wordlist wordlist.txt --resolvers resolvers.txt

FASE 1: Cold Start Bruteforce (caso reale ASM)
FASE 2: Consistenza (stabilità dei risultati)
        """)
    parser.add_argument("--target",    required=True,
                        help="Dominio/i separati da virgola (es: github.com,yahoo.com)")
    parser.add_argument("--wordlist",  required=True, help="Path alla wordlist")
    parser.add_argument("--resolvers", required=True, help="Path al file dei resolver")
    parser.add_argument("--rate",      type=int, default=3000,
                        help="Rate limit per pureDNS (default: 3000)")
    parser.add_argument("--consistency-rounds", type=int, default=3,
                        help="Run per il test di consistenza (default: 3)")
    parser.add_argument("--pause",     type=int, default=60,
                        help="Pausa tra i run in secondi (default: 60)")
    args = parser.parse_args()

    targets = [t.strip() for t in args.target.split(",") if t.strip()]

    print(f"\n{h('DNS BENCHMARK ASM-Grade v6')}")
    print(f"{DIM}pureDNS vs shuffleDNS — parametri equi, no wildcard, validazione trusted{RESET}\n")

    check_deps()
    wordlist_lines = count_lines(args.wordlist)
    num_resolvers = count_lines(args.resolvers)
    # Calcola threads shuffleDNS: 5 thread concorrenti per resolver
    sd_threads = max(num_resolvers * 5, 15)  # minimo 50
    print(info(f"Target: {', '.join(targets)} | Wordlist: {wordlist_lines}"))
    print(info(f"Resolver: {num_resolvers} | pureDNS rate: {args.rate}/s | shuffleDNS threads: {sd_threads} (auto: {num_resolvers}×5)"))
    print(info(f"Wildcard detection: OFF su entrambi"))
    sep()

    for target in targets:
        if len(targets) > 1:
            print(f"\n{'▓'*60}")
            print(f"  {h(f'TARGET: {target}')}")
            print(f"{'▓'*60}")

        # FASE 1
        p1 = phase1_cold_bruteforce(target, args.wordlist, args.resolvers, args.rate, sd_threads)

        # Pausa prima di fase 2
        print(info(f"\nPausa {args.pause}s prima della fase di consistenza..."), flush=True)
        time.sleep(args.pause)

        # FASE 2
        p2 = phase2_consistency(target, args.wordlist, args.resolvers, args.rate,
                                sd_threads, args.consistency_rounds, args.pause)

        # REPORT
        print_final_report(target, wordlist_lines, p1, p2)

if __name__ == "__main__":
    main()
