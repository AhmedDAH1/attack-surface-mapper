"""
Unit Tests for Compliance Checker
"""

import pytest
from src.analyzers.compliance_checker import ComplianceChecker, ComplianceViolation


class TestComplianceChecker:
    """Test ComplianceChecker class"""
    
    def test_initialization(self):
        """Test compliance checker initializes correctly"""
        checker = ComplianceChecker()
        assert checker.violations == []
    
    def test_compliance_violation_creation(self):
        """Test ComplianceViolation dataclass"""
        violation = ComplianceViolation(
            framework='PCI-DSS v4.0',
            control_id='PCI-DSS 4.1',
            control_name='Use Strong Cryptography',
            severity='HIGH',
            description='Test violation',
            affected_assets=['192.168.1.100:80'],
            remediation='Fix it'
        )
        
        assert violation.framework == 'PCI-DSS v4.0'
        assert violation.severity == 'HIGH'
        assert len(violation.affected_assets) == 1
    
    def test_pci_dss_controls_exist(self):
        """Test PCI-DSS controls are defined"""
        checker = ComplianceChecker()
        
        assert 'unencrypted_traffic' in checker.PCI_DSS_CONTROLS
        assert 'default_credentials' in checker.PCI_DSS_CONTROLS
        assert 'weak_ssl' in checker.PCI_DSS_CONTROLS
    
    def test_nist_csf_controls_exist(self):
        """Test NIST CSF controls are defined"""
        checker = ComplianceChecker()
        
        assert 'unencrypted_traffic' in checker.NIST_CSF_CONTROLS
        assert 'vulnerability_management' in checker.NIST_CSF_CONTROLS
    
    def test_cis_controls_exist(self):
        """Test CIS Controls are defined"""
        checker = ComplianceChecker()
        
        assert 'secure_configuration' in checker.CIS_CONTROLS
        assert 'vulnerability_management' in checker.CIS_CONTROLS
    
    def test_compliance_score_calculation(self):
        """Test compliance score calculation"""
        checker = ComplianceChecker()
        
        # No violations = 100 score
        assert checker._calculate_score() == 100.0
        
        # Add violations
        checker.violations = [
            ComplianceViolation(
                framework='PCI-DSS v4.0',
                control_id='test',
                control_name='test',
                severity='CRITICAL',
                description='test',
                affected_assets=[],
                remediation='test'
            )
        ]
        
        score = checker._calculate_score()
        assert score < 100.0
        assert score >= 0
    
    def test_get_summary_empty(self):
        """Test summary with no violations"""
        checker = ComplianceChecker()
        summary = checker.get_summary()
        
        assert summary['total_violations'] == 0
        assert summary['compliance_score'] == 100.0
        assert summary['by_severity']['CRITICAL'] == 0
    
    def test_executive_summary_generation(self):
        """Test executive summary generation"""
        checker = ComplianceChecker()
        summary_text = checker.generate_executive_summary()
        
        assert 'EXECUTIVE SUMMARY' in summary_text
        assert 'Overall Compliance Score' in summary_text
        assert 'PCI-DSS' in summary_text
        assert 'NIST CSF' in summary_text
        assert 'CIS Controls' in summary_text


class TestComplianceScoring:
    """Test compliance scoring logic"""
    
    def test_perfect_score(self):
        """Test 100 score with no violations"""
        checker = ComplianceChecker()
        assert checker._calculate_score() == 100.0
    
    def test_score_with_critical(self):
        """Test score decreases with critical violations"""
        checker = ComplianceChecker()
        
        checker.violations = [
            ComplianceViolation(
                framework='test',
                control_id='test',
                control_name='test',
                severity='CRITICAL',
                description='test',
                affected_assets=[],
                remediation='test'
            )
        ]
        
        score = checker._calculate_score()
        assert score <= 80.0  # Critical = -20 penalty
    
    def test_score_with_high(self):
        """Test score decreases with high violations"""
        checker = ComplianceChecker()
        
        checker.violations = [
            ComplianceViolation(
                framework='test',
                control_id='test',
                control_name='test',
                severity='HIGH',
                description='test',
                affected_assets=[],
                remediation='test'
            )
        ]
        
        score = checker._calculate_score()
        assert score <= 90.0  # High = -10 penalty
    
    def test_score_minimum_zero(self):
        """Test score never goes below 0"""
        checker = ComplianceChecker()
        
        # Add many critical violations
        checker.violations = [
            ComplianceViolation(
                framework='test',
                control_id=f'test{i}',
                control_name='test',
                severity='CRITICAL',
                description='test',
                affected_assets=[],
                remediation='test'
            ) for i in range(10)
        ]
        
        score = checker._calculate_score()
        assert score >= 0
