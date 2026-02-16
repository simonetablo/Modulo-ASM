import sys
import json
import subprocess
import os

def test_run():
    # Input di test
    input_data = {
        "target_list": ["scanme.nmap.org"],
        "params": {
            "scan_type": "fast"
        }
    }
    
    # Creazione file di input temporaneo
    with open('test_input.json', 'w') as f:
        json.dump(input_data, f)
        
    print("Running ASM Module with test input...")
    
    # Esecuzione main.py
    try:
        # Esecuzione tramite subprocess per simulare una chiamata esterna
        result = subprocess.run(
            [sys.executable, 'main.py', '--file', 'test_input.json'],
            capture_output=True,
            text=True,
            check=True
        )
        
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        
        # Verifica che l'output sia un JSON valido
        try:
            output_json = json.loads(result.stdout)
            print("Successfully parsed output JSON.")
            print("Scan Results Keys:", output_json.keys())
        except json.JSONDecodeError:
            print("Failed to parse output as JSON.")
            
    except subprocess.CalledProcessError as e:
        print(f"Execution failed with return code {e.returncode}")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
    finally:
        # Pulizia
        if os.path.exists('test_input.json'):
            os.remove('test_input.json')

if __name__ == "__main__":
    test_run()
