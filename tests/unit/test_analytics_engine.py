"""
Unit Tests for Analytics Engine
"""

import pytest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from src.analyzers.analytics_engine import AnalyticsEngine


class TestAnalyticsEngine:
    """Test AnalyticsEngine class"""
    
    @pytest.fixture
    def temp_dir(self, tmp_path):
        """Create temporary directory for testing"""
        temp_dir = tmp_path
        return temp_dir
        pass
    
    @pytest.fixture
    def analytics(self, temp_dir):
        """Create analytics engine with temp directory"""
        return AnalyticsEngine(history_dir=temp_dir)
    
    def test_initialization(self, analytics, temp_dir):
        """Test analytics engine initializes correctly"""
        assert analytics.history_dir == Path(temp_dir)
        assert analytics.history_dir.exists()
    
    def test_record_scan(self, analytics):
        """Test recording scan data"""
        scan_data = {
            'target': '192.168.1.100',
            'ports_open': 3,
            'services_found': 3,
            'vulnerabilities': 1,
            'critical_issues': 0,
            'high_issues': 1,
            'compliance_score': 70
        }
        
        analytics.record_scan(scan_data)
        
        # Check file was created
        history_file = analytics.history_dir / "192.168.1.100.json"
        assert history_file.exists()
        
        # Check data was stored
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        assert len(history) == 1
        assert history[0]['target'] == '192.168.1.100'
        assert history[0]['metrics']['ports_open'] == 3
    
    def test_record_multiple_scans(self, analytics):
        """Test recording multiple scans"""
        scan_data = {
            'target': '192.168.1.100',
            'ports_open': 3,
            'services_found': 3,
            'vulnerabilities': 1,
            'critical_issues': 0,
            'high_issues': 1,
            'compliance_score': 70
        }
        
        # Record 3 scans
        for i in range(3):
            analytics.record_scan(scan_data)
        
        history_file = analytics.history_dir / "192.168.1.100.json"
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        assert len(history) == 3
    
    def test_get_trend_data_no_history(self, analytics):
        """Test getting trends with no history"""
        trends = analytics.get_trend_data('192.168.1.100')
        assert 'error' in trends
    
    def test_get_risk_heatmap_no_history(self, analytics):
        """Test getting heatmap with no history"""
        heatmap = analytics.get_risk_heatmap('192.168.1.100')
        assert 'error' in heatmap
    
    def test_get_statistics_no_history(self, analytics):
        """Test getting statistics with no history"""
        stats = analytics.get_statistics('192.168.1.100')
        assert 'error' in stats
    
    def test_detect_anomalies_insufficient_data(self, analytics):
        """Test anomaly detection with insufficient data"""
        # Need at least 5 scans
        scan_data = {
            'target': '192.168.1.100',
            'ports_open': 3,
            'vulnerabilities': 1,
            'critical_issues': 0,
            'high_issues': 1,
            'compliance_score': 70
        }
        
        # Record only 3 scans
        for i in range(3):
            analytics.record_scan(scan_data)
        
        anomalies = analytics.detect_anomalies('192.168.1.100')
        assert len(anomalies) == 0


