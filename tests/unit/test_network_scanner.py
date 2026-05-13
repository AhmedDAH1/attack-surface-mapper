"""
Unit Tests for Network Scanner
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import socket
from src.scanners.network_scanner import NetworkScanner, ScanResult


class TestNetworkScanner:
    """Test NetworkScanner class"""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with correct defaults"""
        scanner = NetworkScanner()
        assert scanner.timeout == 1.0
        assert scanner.max_workers == 100
        
        scanner_custom = NetworkScanner(timeout=2.0, max_workers=100)
        assert scanner_custom.timeout == 2.0
        assert scanner_custom.max_workers == 100
    
    def test_scan_result_creation(self):
        """Test ScanResult dataclass"""
        result = ScanResult(
            ip='192.168.1.100',
            port=80,
            service='http',
            banner='Apache/2.4.41',
            state='open'
        )
        
        assert result.ip == '192.168.1.100'
        assert result.port == 80
        assert result.service == 'http'
        assert result.banner == 'Apache/2.4.41'
        assert result.state == 'open'
    
    def test_scan_result_to_dict(self):
        """Test ScanResult to_dict method"""
        result = ScanResult(
            ip='192.168.1.100',
            port=80,
            service='http',
            banner='Apache',
            state='open'
        )
        
        result_dict = result.to_dict()
        assert result_dict['ip'] == '192.168.1.100'
        assert result_dict['port'] == 80
        assert result_dict['service'] == 'http'
        assert result_dict['banner'] == 'Apache'
        assert result_dict['state'] == 'open'
    
    def test_scanner_has_scan_method(self):
        """Test scanner has scan method"""
        scanner = NetworkScanner()
        assert hasattr(scanner, 'scan')
        assert callable(scanner.scan)
