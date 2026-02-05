"""
ShadowHawk Platform - Threat Modeling Engine Tests

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

import pytest
from src.shadowhawk.domain.models.asset import Asset, AssetType, Criticality
from src.shadowhawk.application.engines.threat_modeling import ThreatModelingEngine


class TestThreatModelingEngine:
    """Test suite for Threat Modeling Engine."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.engine = ThreatModelingEngine()
    
    def test_analyze_application_asset(self):
        """Test threat analysis for application asset."""
        asset = Asset(
            name="Web Application",
            asset_type=AssetType.APPLICATION,
            criticality=Criticality.HIGH
        )
        
        threats = self.engine.analyze_asset(asset)
        
        assert len(threats) > 0
        assert any("Spoofing" in t.title for t in threats)
        assert all(t.asset_id == asset.id for t in threats)
    
    def test_analyze_database_asset(self):
        """Test threat analysis for database asset."""
        asset = Asset(
            name="Customer Database",
            asset_type=AssetType.DATABASE,
            criticality=Criticality.CRITICAL
        )
        
        threats = self.engine.analyze_asset(asset)
        
        assert len(threats) > 0
        assert any("Tampering" in t.title for t in threats)
    
    def test_generate_threat_report(self):
        """Test threat report generation."""
        asset = Asset(
            name="API Server",
            asset_type=AssetType.API,
            criticality=Criticality.HIGH
        )
        
        threats = self.engine.analyze_asset(asset)
        report = self.engine.generate_threat_report(asset, threats)
        
        assert report["threat_count"] == len(threats)
        assert "stride_summary" in report
        assert "recommendations" in report
    
    def test_analyze_multiple_assets(self):
        """Test analysis of multiple assets."""
        assets = [
            Asset(name="App1", asset_type=AssetType.APPLICATION, criticality=Criticality.HIGH),
            Asset(name="DB1", asset_type=AssetType.DATABASE, criticality=Criticality.CRITICAL),
        ]
        
        results = self.engine.analyze_multiple_assets(assets)
        
        assert len(results) == 2
        for asset in assets:
            assert asset.id in results
            assert len(results[asset.id]) > 0
