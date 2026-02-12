import json
import io
import sys
import unittest
from unittest.mock import MagicMock, patch

# Assuming main.py is in the parent directory or accessible path
sys.path.append('c:\\Users\\simon\\Documents\\Modulo-ASM')
# We need to import main but it is not a package, so let's import it via importlib to be safe or just standard import since sys.path includes it
import main

class TestHttpExtraction(unittest.TestCase):
    
    @patch('main.NmapTool')
    @patch('main.HttpxTool')
    def test_main_extraction(self, MockHttpxTool, MockNmapTool):
        # Mock input data
        input_data = {
            "domains": ["example.com"],
            "params": {"scan_type": "fast"}
        }
        
        # Mock Nmap results with standard and non-standard HTTP ports
        mock_nmap_instance = MockNmapTool.return_value
        # The structure of nmap result: {domain: { 'tcp': { port: { 'state': ..., 'name': ... } } } }
        mock_nmap_instance.get_results.return_value = json.dumps({
            "example.com": {
                "addresses": {"ipv4": "192.168.1.1"},
                "tcp": {
                    "80": {"state": "open", "name": "http"},
                    "443": {"state": "open", "name": "https"},
                    "8080": {"state": "open", "name": "http-proxy"}, # Should be detected
                    "8443": {"state": "open", "name": "ssl/http"}, # Should be detected as https
                    "3000": {"state": "open", "name": "http-alt"}, # Should be detected
                    "22": {"state": "open", "name": "ssh"} # Should NOT be detected
                }
            }
        })

        # Mock Httpx run to capture the targets passed to it
        mock_httpx_instance = MockHttpxTool.return_value
        mock_httpx_instance.results = {} 

        # Capture the targets passed to httpx_tool.run
        captured_targets = []
        def side_effect_run(targets, params):
            # This captures targets passed to httpx_tool.run
            captured_targets.extend(targets)
        
        mock_httpx_instance.run.side_effect = side_effect_run

        # Capture stdout/stderr to suppress prints
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        
        # Run main with mocked args and captured output
        # Also need to mock sys.argv to simulate command line call
        with patch('sys.argv', ['main.py', '--input', json.dumps(input_data)]), \
             patch('sys.stdout', captured_stdout), \
             patch('sys.stderr', captured_stderr):
            try:
                main.main()
            except SystemExit:
                pass # main() calls sys.exit(0) at the end usually.
        
        print(f"Captured targets: {captured_targets}")
        
        # Expected targets SHOULD include standard and non-standard ports
        # Standard ports 80/443 might be passed as http://example.com and https://example.com
        # Non-standard ports should be http://example.com:8080 or https://example.com:8443
        
        # We perform soft assertions for now to show what is missing
        # The goal is to verify that non-standard ports are NOT currently captured but WILL be after fix.
        
        # Standard ports are currently captured
        self.assertIn("example.com:80", captured_targets, "Standard HTTP port 80 not detected")
        self.assertIn("example.com:443", captured_targets, "Standard HTTPS port 443 not detected")
        
        # Non-standard ports - these assertions should now PASS
        self.assertIn("example.com:8080", captured_targets, "Port 8080 not detected")
        self.assertIn("example.com:8443", captured_targets, "Port 8443 not detected")
        self.assertIn("example.com:3000", captured_targets, "Port 3000 not detected")
        
        # Verify exclusion of non-web services
        self.assertNotIn("example.com:22", captured_targets, "SSH port 22 should NOT be detected")

if __name__ == '__main__':
    unittest.main()
