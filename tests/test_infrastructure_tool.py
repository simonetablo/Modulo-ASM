import unittest
from unittest.mock import MagicMock, patch
import sys
import dns.resolver

# Ensure tools package is importable
sys.path.append('c:\\Users\\simon\\Documents\\Modulo-ASM')
from tools.infrastructure_tool import InfrastructureTool

class TestInfrastructureTool(unittest.TestCase):
    
    @patch('tools.infrastructure_tool.IPWhois')
    @patch('tools.infrastructure_tool.dns.resolver.Resolver') 
    @patch('socket.gethostbyname')
    def test_aws_detection(self, mock_gethostbyname, mock_resolver_cls, mock_ipwhois_cls):
        # Setup mocks
        mock_gethostbyname.return_value = "1.2.3.4"
        
        # Mock IPWhois lookup_rdap
        mock_ipwhois_instance = mock_ipwhois_cls.return_value
        mock_ipwhois_instance.lookup_rdap.return_value = {
            'asn_description': 'AMAZON-02',
            'network': {'name': 'Amazon.com'},
            'asn': '16509'
        }
        
        # Mock DNS Resolver (RBL shouldn't be called if cloud is detected, but just in case)
        mock_resolver = mock_resolver_cls.return_value
        
        tool = InfrastructureTool()
        tool.run(["example.com"], {})
        
        result = tool.results.get("example.com")
        self.assertIsNotNone(result)
        self.assertTrue(result["is_cloud"])
        self.assertEqual(result["cloud_provider"], "Amazon AWS")

    @patch('tools.infrastructure_tool.IPWhois')
    @patch('tools.infrastructure_tool.dns.resolver.Resolver')
    @patch('socket.gethostbyname')
    def test_rbl_dynamic_detection(self, mock_gethostbyname, mock_resolver_cls, mock_ipwhois_cls):
        # Setup mocks
        mock_gethostbyname.return_value = "1.2.3.4"
        
        # Mock IPWhois (Not Cloud)
        mock_ipwhois_instance = mock_ipwhois_cls.return_value
        mock_ipwhois_instance.lookup_rdap.return_value = {
            'asn_description': 'GENERIC-ISP',
            'network': {'name': 'Generic ISP'},
            'asn': '12345'
        }
        
        # Mock DNS Resolver to simulate RBL HIT
        mock_resolver = mock_resolver_cls.return_value
        # resolve should return something (not raise) to simulate HIT
        mock_resolver.resolve.return_value = ["127.0.0.10"] 
        
        tool = InfrastructureTool()
        tool.run(["1.2.3.4"], {})
        
        result = tool.results.get("1.2.3.4")
        self.assertTrue(result["is_dynamic"])

    @patch('tools.infrastructure_tool.IPWhois')
    @patch('tools.infrastructure_tool.dns.resolver.Resolver')
    @patch('socket.gethostbyname')
    def test_clean_detection(self, mock_gethostbyname, mock_resolver_cls, mock_ipwhois_cls):
        # Setup mocks
        mock_gethostbyname.return_value = "1.2.3.4"
        
        # Mock IPWhois (Not Cloud)
        mock_ipwhois_instance = mock_ipwhois_cls.return_value
        mock_ipwhois_instance.lookup_rdap.return_value = {
            'asn_description': 'STATIC-ISP',
            'network': {'name': 'Static ISP'},
            'asn': '54321'
        }
        
        # Mock DNS Resolver to simulate RBL MISS (raise NXDOMAIN)
        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        
        tool = InfrastructureTool()
        tool.run(["1.2.3.4"], {})
        
        result = tool.results.get("1.2.3.4")
        self.assertFalse(result["is_dynamic"])
        self.assertFalse(result["is_cloud"])

if __name__ == '__main__':
    unittest.main()
