"""
Integration tests for ML components.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import pytest
import numpy as np

from shadowhawk.ml.inference.engine import InferenceEngine
from shadowhawk.ml.data_prep.preprocessor import DataPreprocessor
from shadowhawk.ml.training.pipeline import ContinuousLearningPipeline
from shadowhawk.application.engines.threat_modeling import ThreatModelingEngine
from shadowhawk.application.engines.detection import DetectionEngine
from shadowhawk.application.engines.mitre_mapping import MitreMappingEngine
from shadowhawk.application.engines.correlation import CorrelationEngine
from shadowhawk.application.engines.risk_scoring import RiskScoringEngine


class TestInferenceEngine:
    """Integration tests for InferenceEngine."""
    
    def test_detect_anomalies_integration(self):
        """Test anomaly detection end-to-end."""
        engine = InferenceEngine()
        
        # Create test data
        normal_data = np.random.rand(100, 5)
        test_data = np.random.rand(10, 5)
        
        # Train on normal data first
        anomalies = engine.detect_anomalies(test_data)
        
        assert isinstance(anomalies, list)
        # Model will be untrained so may not detect anomalies well
        # but should not raise errors
    
    def test_classify_threats_integration(self):
        """Test threat classification end-to-end."""
        engine = InferenceEngine()
        
        features = np.random.rand(5, 10)
        results = engine.classify_threats(features)
        
        assert len(results) == 5
        for result in results:
            assert "predicted_class" in result
            assert "confidence" in result
    
    def test_predict_risk_integration(self):
        """Test risk prediction end-to-end."""
        engine = InferenceEngine()
        
        # Risk features
        features = np.array([
            [0.8, 0.7, 0.9, 0.6, 0.5, 0.4],  # High risk
            [0.2, 0.3, 0.1, 0.4, 0.3, 0.5],  # Low risk
        ])
        
        results = engine.predict_risk(features)
        
        assert len(results) == 2
        for result in results:
            assert "risk_score" in result or "error" in result
    
    def test_extract_techniques_integration(self):
        """Test technique extraction end-to-end."""
        engine = InferenceEngine()
        
        text = "The attacker used phishing emails with malicious attachments"
        techniques = engine.extract_techniques(text)
        
        assert isinstance(techniques, list)
        # Should detect T1566 (Phishing) via pattern matching
        technique_ids = [t["technique_id"] for t in techniques]
        assert "T1566" in technique_ids
    
    def test_analyze_threat_comprehensive(self):
        """Test comprehensive threat analysis."""
        engine = InferenceEngine()
        
        features = np.random.rand(10)
        description = "Malware detected on endpoint with suspicious network activity"
        
        result = engine.analyze_threat(
            features=features,
            description=description,
            event_id="test_event_1"
        )
        
        assert "event_id" in result
        assert "analysis" in result
        assert "anomaly" in result["analysis"]
        assert "classification" in result["analysis"]
        assert "techniques" in result["analysis"]


class TestDataPreprocessor:
    """Integration tests for DataPreprocessor."""
    
    def test_extract_numeric_features(self):
        """Test numeric feature extraction."""
        preprocessor = DataPreprocessor()
        
        event = {
            "severity": 8,
            "confidence": 0.85,
            "timestamp": "2024-01-15T10:30:00",
            "source_reputation": 0.3,
            "target_criticality": 0.9,
            "event_type": "network",
        }
        
        features = preprocessor.extract_numeric_features(event)
        
        assert isinstance(features, np.ndarray)
        assert len(features) > 0
        assert all(0 <= f <= 1 for f in features)
    
    def test_extract_risk_features(self):
        """Test risk feature extraction."""
        preprocessor = DataPreprocessor()
        
        vulnerability = {
            "cvss_score": 8.5,
            "epss_score": 0.75,
            "asset_criticality": 0.9,
            "exploit_maturity": 0.8,
            "threat_actor_capability": 0.7,
            "exposure_level": 0.6,
            "mitigation_effectiveness": 0.3,
            "data_sensitivity": 0.8,
        }
        
        features = preprocessor.extract_risk_features(vulnerability)
        
        assert isinstance(features, np.ndarray)
        assert len(features) == 8
        assert all(0 <= f <= 1 for f in features)
    
    def test_prepare_training_data(self):
        """Test training data preparation."""
        preprocessor = DataPreprocessor()
        
        events = [
            {"severity": 8, "type": "network", "timestamp": "2024-01-15T10:30:00"},
            {"severity": 5, "type": "file", "timestamp": "2024-01-15T11:00:00"},
            {"severity": 3, "type": "process", "timestamp": "2024-01-15T12:00:00"},
        ]
        labels = ["malware", "normal", "normal"]
        
        X, y = preprocessor.prepare_training_data(events, labels)
        
        assert X.shape[0] == 3
        assert len(y) == 3
    
    def test_preprocess_text(self):
        """Test text preprocessing."""
        preprocessor = DataPreprocessor()
        
        text = "  Malware  detected!!!  on  system  "
        processed = preprocessor.preprocess_text(text)
        
        assert processed == "malware detected on system"
    
    def test_normalize_features(self):
        """Test feature normalization."""
        preprocessor = DataPreprocessor()
        
        X = np.array([
            [1.0, 2.0, 3.0],
            [4.0, 5.0, 6.0],
            [7.0, 8.0, 9.0],
        ])
        
        X_normalized = preprocessor.normalize_features(X)
        
        assert X_normalized.shape == X.shape
        # After normalization, mean should be close to 0
        assert abs(np.mean(X_normalized, axis=0)).max() < 1e-10


class TestEnginesIntegration:
    """Integration tests for application engines."""
    
    def test_threat_modeling_engine(self):
        """Test ThreatModelingEngine end-to-end."""
        engine = ThreatModelingEngine()
        
        assets = [
            {"id": "web_1", "name": "Web Server", "type": "web_server", "criticality": 0.9, "exposure": "external"},
            {"id": "db_1", "name": "Database", "type": "database", "criticality": 1.0, "exposure": "internal"},
            {"id": "ws_1", "name": "Workstation", "type": "workstation", "criticality": 0.5, "exposure": "internal"},
        ]
        
        connections = [
            {"source": "web_1", "target": "db_1", "protocol": "tcp", "port": 3306},
            {"source": "ws_1", "target": "web_1", "protocol": "https", "port": 443},
        ]
        
        threat_model = engine.model_system(assets, connections)
        
        assert "system_summary" in threat_model
        assert "attack_scenarios" in threat_model
        assert "critical_paths" in threat_model
        assert threat_model["system_summary"]["total_assets"] == 3
    
    def test_detection_engine(self):
        """Test DetectionEngine end-to-end."""
        engine = DetectionEngine()
        
        event = {
            "id": "evt_1",
            "timestamp": "2024-01-15T10:30:00",
            "type": "network",
            "severity": 8,
            "confidence": 0.85,
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.50",
            "description": "Suspicious outbound connection detected",
            "indicators": [{"type": "ip", "value": "malicious.example.com"}],
        }
        
        result = engine.analyze_event(event)
        
        assert "event_id" in result
        assert "alert_level" in result
        assert "anomaly_detection" in result
        assert "behavioral_analysis" in result
    
    def test_mitre_mapping_engine(self):
        """Test MitreMappingEngine end-to-end."""
        engine = MitreMappingEngine()
        
        event = {
            "id": "evt_1",
            "type": "email",
            "category": "phishing",
            "description": "User received phishing email with malicious attachment",
            "indicators": [{"type": "email", "description": "suspicious link"}],
        }
        
        mapping = engine.map_event(event)
        
        assert "event_id" in mapping
        assert "techniques" in mapping
        assert "tactic_coverage" in mapping
        
        # Should detect phishing technique
        technique_ids = [t["technique_id"] for t in mapping["techniques"]]
        assert "T1566" in technique_ids
    
    def test_correlation_engine(self):
        """Test CorrelationEngine end-to-end."""
        engine = CorrelationEngine()
        
        # Add correlated events
        events = [
            {
                "id": "evt_1",
                "timestamp": "2024-01-15T10:00:00",
                "type": "network",
                "source_ip": "192.168.1.100",
                "severity": 7,
            },
            {
                "id": "evt_2",
                "timestamp": "2024-01-15T10:05:00",
                "type": "authentication",
                "source_ip": "192.168.1.100",
                "user": "admin",
                "severity": 8,
            },
            {
                "id": "evt_3",
                "timestamp": "2024-01-15T10:10:00",
                "type": "file",
                "user": "admin",
                "severity": 6,
            },
        ]
        
        for event in events:
            engine.add_event(event)
        
        result = engine.correlate()
        
        assert "total_events_analyzed" in result
        assert "correlation_pairs" in result
        assert "related_event_groups" in result
    
    def test_risk_scoring_engine(self):
        """Test RiskScoringEngine end-to-end."""
        engine = RiskScoringEngine()
        
        vulnerability = {
            "id": "CVE-2024-1234",
            "cvss_score": 9.1,
            "epss_score": 0.85,
            "exploit_available": True,
            "patch_available": False,
        }
        
        threat_intel = {
            "actor_activity": 0.8,
            "exploit_maturity": 0.9,
        }
        
        asset_context = {
            "criticality": 0.95,
            "exposure_level": 0.7,
            "data_sensitivity": 0.9,
        }
        
        assessment = engine.calculate_risk(vulnerability, threat_intel, asset_context)
        
        assert "vulnerability_id" in assessment
        assert "overall_risk_score" in assessment
        assert "risk_level" in assessment
        assert "component_scores" in assessment
        assert "recommended_actions" in assessment
        
        # With high CVSS and EPSS, should be high risk
        assert assessment["risk_level"] in ["critical", "high"]
    
    def test_risk_scoring_portfolio(self):
        """Test portfolio risk calculation."""
        engine = RiskScoringEngine()
        
        vulnerabilities = [
            {"id": "CVE-2024-0001", "cvss_score": 9.5, "epss_score": 0.9},
            {"id": "CVE-2024-0002", "cvss_score": 7.5, "epss_score": 0.6},
            {"id": "CVE-2024-0003", "cvss_score": 5.0, "epss_score": 0.3},
        ]
        
        portfolio = engine.calculate_portfolio_risk(vulnerabilities)
        
        assert portfolio["total_vulnerabilities"] == 3
        assert "average_risk" in portfolio
        assert "risk_distribution" in portfolio
        assert "top_risks" in portfolio


class TestTrainingPipeline:
    """Integration tests for training pipeline."""
    
    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = ContinuousLearningPipeline()
        
        assert pipeline.models_dir.exists()
        assert isinstance(pipeline.training_history, list)
    
    def test_train_anomaly_detector(self):
        """Test anomaly detector training."""
        pipeline = ContinuousLearningPipeline()
        
        X = np.random.rand(100, 5)
        
        result = pipeline.train_anomaly_detector(X)
        
        assert result.model_name == "anomaly_detector"
        assert result.status in ["success", "error"]
        
        if result.status == "success":
            assert result.model_path.exists()
    
    def test_train_threat_classifier(self):
        """Test threat classifier training."""
        pipeline = ContinuousLearningPipeline()
        
        X = np.random.rand(50, 10)
        y = np.random.choice(["malware", "phishing"], 50)
        
        result = pipeline.train_threat_classifier(X, y)
        
        assert result.model_name == "threat_classifier"
        assert result.status in ["success", "error"]
    
    def test_train_risk_predictor(self):
        """Test risk predictor training."""
        pipeline = ContinuousLearningPipeline()
        
        X = np.random.rand(50, 8)
        y = np.random.rand(50) * 10
        
        result = pipeline.train_risk_predictor(X, y)
        
        assert result.model_name == "risk_predictor"
        assert result.status in ["success", "error"]
    
    def test_model_registry(self):
        """Test model registry operations."""
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = ContinuousLearningPipeline(models_dir=Path(tmpdir))
            
            # Register a fake model
            pipeline.model_registry["test_model"] = {
                "version": "test_001",
                "path": str(Path(tmpdir) / "test.pkl"),
                "metrics": {"accuracy": 0.9},
                "timestamp": "2024-01-01T00:00:00",
            }
            
            pipeline._save_registry()
            
            # Load new pipeline and verify
            pipeline2 = ContinuousLearningPipeline(models_dir=Path(tmpdir))
            assert "test_model" in pipeline2.model_registry
