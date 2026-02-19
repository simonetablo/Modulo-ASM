import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.permutation_tool import PermutationTool
from tools.subdomain_enum_tool import SubdomainEnumTool

def test_workflow():
    print("Testing Permutation Workflow & SubdomainEnumTool Refactor...")
    
    # 1. Initialize tools
    print("[*] Initializing tools...")
    perm_tool = PermutationTool()
    sub_tool = SubdomainEnumTool()

    # --- Permutation + Resolve Workflow ---
    print("\n--- Testing Permutation + Resolve Workflow ---")
    seed_domains = ["scanme.sh"]
    print(f"[*] Running PermutationTool on {seed_domains}...")
    
    perm_params = {
        "flags": ["-limit", "20"] 
    }
    
    perm_tool.run(seed_domains, perm_params)
    perm_results = json.loads(perm_tool.get_results())
    
    candidates = []
    for seed in seed_domains:
        if seed in perm_results and "permutations" in perm_results[seed]:
            candidates.extend(perm_results[seed]["permutations"])
            
    print(f"[*] Generated {len(candidates)} permutation candidates.")
    
    # Inject a known valid domain to ensure resolution works
    known_valid = "scanme.nmap.org"
    if known_valid not in candidates:
         candidates.append(known_valid)
         print(f"[*] Added known valid domain '{known_valid}' to candidates for verification.")

    print(f"[*] Running SubdomainEnumTool (mode='resolve') on {len(candidates)} candidates...")
    
    resolve_params = {"method": "resolve"}
    sub_tool.run(candidates, resolve_params)
    sub_results = json.loads(sub_tool.get_results())
    
    if "resolved_domains" in sub_results:
        resolved = sub_results["resolved_domains"]["domains"]
        print(f"[*] Resolved {len(resolved)} valid domains.")
        print(f"[*] Valid domains: {resolved}")
        if known_valid in resolved:
             print("[SUCCESS] Known valid domain was correctly resolved.")
        else:
             print("[WARNING] Known valid domain was NOT resolved (might be network issue or puredns config).")
    else:
        print("[FAIL] 'resolved_domains' key not found in results.")

    # --- Bruteforce Workflow ---
    print("\n--- Testing Bruteforce Workflow (Regression Test) ---")
    # For bruteforce, we need a wordlist. SubdomainEnumTool uses 'wordlists/test_subs.txt' by default.
    # We'll create a dummy one if it doesn't exist.
    if not os.path.exists("wordlists/test_subs.txt"):
        print("[*] Creating dummy wordlist for bruteforce test...")
        os.makedirs("wordlists", exist_ok=True)
        with open("wordlists/test_subs.txt", "w") as f:
            f.write("www\nmail\nftp\n")
            
    target = "scanme.sh"
    print(f"[*] Running SubdomainEnumTool (mode='bruteforce') on {target}...")
    brute_params = {"method": "bruteforce", "scan_type": "fast"}
    
    sub_tool.run([target], brute_params)
    brute_results = json.loads(sub_tool.get_results())
    
    if target in brute_results and "discovered_subdomains" in brute_results[target]:
        discovered = brute_results[target]["discovered_subdomains"]
        print(f"[*] Discovered {len(discovered)} subdomains via bruteforce.")
        print(f"[*] Discovered: {discovered}")
    else:
        print(f"[FAIL] Bruteforce results structure incorrect for {target}.")


if __name__ == "__main__":
    try:
        test_workflow()
        print("\n[OK] All tests completed.")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
