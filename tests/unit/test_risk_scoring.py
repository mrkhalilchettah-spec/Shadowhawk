"""
ShadowHawk Platform - Risk Scoring Engine Tests

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

import pytest
from src.shadowhawk.domain.models.finding import Finding, FindingSeverity
from src.shadowhawk.domain.models.asset import Asset, AssetType, Criticality
from src.shadowhawk.application.engines.risk_scoring import RiskScoringEngine


class TestRiskScoringEngine:
    """Test suite for Risk Scoring Engine."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.engine = RiskScoringEngine()
    
    def test_calculate_risk_critical_finding(self):
        """Test risk calculation for critical finding."""
        finding = Finding(
            title="Critical Vulnerability",
            description="Test vulnerability",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8
        )
        
        risk = self.engine.calculate_risk(finding)
        
        assert risk.risk_score >= 7.0
        assert risk.risk_level.value in ["critical", "high"]
    
    def test_calculate_risk_with_asset(self):
        """Test risk calculation with asset context."""
        finding = Finding(
            title="Vulnerability",
            description="Test",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5
        )
        
        asset = Asset(
            name="Critical System",
            asset_type=AssetType.SERVER,
            criticality=Criticality.CRITICAL
        )
        
        risk = self.engine.calculate_risk(finding, asset)
        
        assert risk.risk_score > 0
        assert risk.asset_id == asset.id
    
    def test_cvss_score_calculation(self):
        """Test CVSS score calculation."""
        score = self.engine.calculate_cvss_score(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality_impact="H",
            integrity_impact="H",
            availability_impact="H"
        )
        
        assert 0.0 <= score <= 10.0
        assert score >= 9.0
