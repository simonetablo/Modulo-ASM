import unittest
from urllib.parse import urlparse

class TestHttpxIntegration(unittest.TestCase):
    def test_integration_logic(self):
        # Current logic simulation from main.py
        # domain_key = url.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Setup
        final_results = {
            "example.com": {"web_recon": {}}
        }
        
        httpx_results = {
            "example.com:8080": {"status": 200, "title": "Test"},
            "example.com:8443": {"status": 200, "title": "Test SSL"},
            "example.com:80": {"status": 200, "title": "Default"}
        }
        
        # Integration logic PROPOSAL: Handle schematic-less URLs by forcing //
        for url, data in httpx_results.items():
            # If no scheme is present, assume // to force netloc parsing
            if "://" not in url:
                parsed_url = urlparse("//" + url)
            else:
                parsed_url = urlparse(url)
                
            domain_key = parsed_url.hostname
            
            print(f"URL: {url} -> Extracted Key: {domain_key}")
            
            if domain_key in final_results:
                final_results[domain_key]["web_recon"][url] = data
            else:
                print(f"FAILED to match {domain_key} with existing keys: {list(final_results.keys())}")

        # Assertions
        # This one typically passes
        self.assertIn("example.com:80", final_results["example.com"]["web_recon"], "Standard URL should be integrated")
        
        # These are expected to FAIL with current logic
        self.assertIn("example.com:8080", final_results["example.com"]["web_recon"], "Port 8080 URL should be integrated")
        self.assertIn("example.com:8443", final_results["example.com"]["web_recon"], "Port 8443 URL should be integrated")

if __name__ == '__main__':
    unittest.main()
