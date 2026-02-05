"""
Unit tests for ML models.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import tempfile
from pathlib import Path

import numpy as np
import pytest

from shadowhawk.ml.models.anomaly_detector import AnomalyDetector
from shadowhawk.ml.models.correlation_model import CorrelationModel
from shadowhawk.ml.models.risk_predictor import RiskPredictor
from shadowhawk.ml.models.technique_extractor import TechniqueExtractor
from shadowhawk.ml.models.threat_classifier import ThreatClassifier


class TestAnomalyDetector:
    """Tests for AnomalyDetector."""
    
    def test_initialization(self):
        """Test model initialization."""
        model = AnomalyDetector()
        assert model.contamination == 0.1
        assert not model.is_fitted
    
    def test_fit(self):
        """Test model fitting."""
        model = AnomalyDetector()
        X = np.random.rand(100, 5)
        
        result = model.fit(X)
        assert result is model
        assert model.is_fitted
    
    def test_predict(self):
        """Test prediction."""
        model = AnomalyDetector()
        X_train = np.random.rand(100, 5)
        X_test = np.random.rand(10, 5)
        
        model.fit(X_train)
        predictions, confidences = model.predict(X_test, return_confidence=True)
        
        assert len(predictions) == 10
        assert len(confidences) == 10
        assert all(p in [-1, 1] for p in predictions)
        assert all(0 <= c <= 1 for c in confidences)
    
    def test_detect_anomalies(self):
        """Test anomaly detection."""
        model = AnomalyDetector()
        X_train = np.random.rand(100, 5)
        X_test = np.random.rand(10, 5)
        
        model.fit(X_train)
        anomalies = model.detect_anomalies(X_test, threshold=0.5)
        
        assert isinstance(anomalies, list)
        for anomaly in anomalies:
            assert "index" in anomaly
            assert "is_anomaly" in anomaly
            assert "anomaly_score" in anomaly
    
    def test_save_load(self):
        """Test model save and load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model = AnomalyDetector()
            X = np.random.rand(100, 5)
            model.fit(X)
            
            path = Path(tmpdir) / "model.pkl"
            model.save(path)
            
            loaded = AnomalyDetector.load(path)
            assert loaded.is_fitted
            assert loaded.contamination == model.contamination


class TestThreatClassifier:
    """Tests for ThreatClassifier."""
    
    def test_initialization(self):
        """Test model initialization."""
        model = ThreatClassifier()
        assert model.use_text_features is True
        assert not model.is_fitted
    
    def test_fit_predict(self):
        """Test fitting and prediction."""
        model = ThreatClassifier(use_text_features=False)
        
        X = np.random.rand(100, 10)
        y = np.random.choice(["malware", "phishing", "intrusion"], 100)
        
        model.fit(X, y)
        assert model.is_fitted
        
        X_test = np.random.rand(5, 10)
        predictions, probabilities = model.predict(X_test, return_proba=True)
        
        assert len(predictions) == 5
        assert probabilities.shape == (5, 3)
    
    def test_classify_threat(self):
        """Test threat classification."""
        model = ThreatClassifier(use_text_features=False)
        
        X = np.random.rand(50, 10)
        y = np.random.choice(["malware", "phishing"], 50)
        model.fit(X, y)
        
        X_test = np.random.rand(3, 10)
        results = model.classify_threat(X_test, top_k=2)
        
        assert len(results) == 3
        for result in results:
            assert "predicted_class" in result
            assert "confidence" in result
            assert "top_predictions" in result
            assert len(result["top_predictions"]) <= 2


class TestRiskPredictor:
    """Tests for RiskPredictor."""
    
    def test_initialization(self):
        """Test model initialization."""
        model = RiskPredictor()
        assert not model.is_fitted
        assert len(model.RISK_FACTORS) == 8
    
    def test_fit_predict(self):
        """Test fitting and prediction."""
        model = RiskPredictor()
        
        X = np.random.rand(100, 8)
        y = np.random.rand(100) * 10  # Risk scores 0-10
        
        model.fit(X, y)
        assert model.is_fitted
        
        X_test = np.random.rand(5, 8)
        predictions, uncertainties = model.predict(X_test, return_confidence=True)
        
        assert len(predictions) == 5
        assert len(uncertainties) == 5
        assert all(0 <= p <= 10 for p in predictions)
        assert all(u >= 0 for u in uncertainties)
    
    def test_predict_risk_with_details(self):
        """Test detailed risk prediction."""
        model = RiskPredictor()
        
        X = np.random.rand(50, 8)
        y = np.random.rand(50) * 10
        model.fit(X, y)
        
        X_test = np.random.rand(3, 8)
        results = model.predict_risk_with_details(X_test)
        
        assert len(results) == 3
        for result in results:
            assert "risk_score" in result
            assert "risk_level" in result
            assert result["risk_level"] in ["critical", "high", "medium", "low", "minimal"]
    
    def test_calculate_exploitability_score(self):
        """Test exploitability score calculation."""
        model = RiskPredictor()
        
        score = model.calculate_exploitability_score(
            epss_score=0.8,
            exploit_maturity=0.7,
            patch_availability=0.3
        )
        
        assert 0 <= score <= 1
    
    def test_get_feature_importance(self):
        """Test feature importance extraction."""
        model = RiskPredictor()
        
        X = np.random.rand(50, 8)
        y = np.random.rand(50) * 10
        model.fit(X, y)
        
        importance = model.get_feature_importance()
        assert len(importance) == 8
        assert all(factor in importance for factor in model.RISK_FACTORS)


class TestTechniqueExtractor:
    """Tests for TechniqueExtractor."""
    
    def test_initialization(self):
        """Test model initialization."""
        model = TechniqueExtractor(use_pretrained=False)
        assert model.use_pretrained is False
    
    def test_extract_techniques_pattern_based(self):
        """Test pattern-based technique extraction."""
        model = TechniqueExtractor(use_pretrained=False)
        
        text = "The attacker used phishing emails to deliver malware"
        techniques = model.extract_techniques(text)
        
        assert isinstance(techniques, list)
        # Should find T1566 (Phishing)
        technique_ids = [t["technique_id"] for t in techniques]
        assert "T1566" in technique_ids
    
    def test_extract_techniques_multiple(self):
        """Test extraction of multiple techniques."""
        model = TechniqueExtractor(use_pretrained=False)
        
        text = "The attacker used phishing and credential dumping with process injection"
        techniques = model.extract_techniques(text)
        
        technique_ids = [t["technique_id"] for t in techniques]
        assert len(technique_ids) >= 2
    
    def test_batch_extract(self):
        """Test batch technique extraction."""
        model = TechniqueExtractor(use_pretrained=False)
        
        texts = [
            "Phishing attack detected",
            "Credential dumping observed",
            "Process injection identified"
        ]
        
        results = model.batch_extract(texts)
        assert len(results) == 3
        for techniques in results:
            assert isinstance(techniques, list)


class TestCorrelationModel:
    """Tests for CorrelationModel."""
    
    def test_initialization(self):
        """Test model initialization."""
        model = CorrelationModel()
        assert model.similarity_threshold == 0.7
        assert model.min_cluster_size == 3
    
    def test_add_event_and_build_graph(self):
        """Test adding events and building graph."""
        model = CorrelationModel(similarity_threshold=0.5)
        
        # Add events
        events = {
            "event_1": np.array([1.0, 0.0, 0.0]),
            "event_2": np.array([0.9, 0.1, 0.0]),
            "event_3": np.array([0.0, 1.0, 0.0]),
        }
        
        for event_id, features in events.items():
            model.add_event(event_id, features)
        
        model.build_graph()
        
        assert model.is_fitted
        assert len(model.graph.nodes) == 3
    
    def test_find_correlated_events(self):
        """Test finding correlated events."""
        model = CorrelationModel(similarity_threshold=0.5)
        
        events = {
            "event_1": np.array([1.0, 0.0, 0.0]),
            "event_2": np.array([0.95, 0.05, 0.0]),
            "event_3": np.array([0.0, 1.0, 0.0]),
        }
        
        for event_id, features in events.items():
            model.add_event(event_id, features)
        
        model.build_graph()
        
        correlated = model.find_correlated_events("event_1", max_depth=1)
        assert isinstance(correlated, list)
    
    def test_detect_campaigns(self):
        """Test campaign detection."""
        model = CorrelationModel(similarity_threshold=0.5, min_cluster_size=2)
        
        # Create a cluster of related events
        events = {
            f"event_{i}": np.array([0.9, 0.1 * i, 0.0])
            for i in range(5)
        }
        
        for event_id, features in events.items():
            model.add_event(event_id, features)
        
        model.build_graph()
        
        campaigns = model.detect_campaigns()
        assert isinstance(campaigns, list)
    
    def test_find_attack_paths(self):
        """Test finding attack paths."""
        model = CorrelationModel(similarity_threshold=0.5)
        
        events = {
            "event_1": np.array([1.0, 0.0, 0.0]),
            "event_2": np.array([0.9, 0.1, 0.0]),
            "event_3": np.array([0.8, 0.2, 0.0]),
        }
        
        for event_id, features in events.items():
            model.add_event(event_id, features)
        
        model.build_graph()
        
        paths = model.find_attack_paths("event_1", "event_3")
        assert isinstance(paths, list)
    
    def test_save_load(self):
        """Test model save and load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model = CorrelationModel()
            
            events = {
                "event_1": np.array([1.0, 0.0]),
                "event_2": np.array([0.9, 0.1]),
            }
            
            for event_id, features in events.items():
                model.add_event(event_id, features)
            
            model.build_graph()
            
            path = Path(tmpdir) / "model.pkl"
            model.save(path)
            
            loaded = CorrelationModel.load(path)
            assert loaded.is_fitted
            assert len(loaded.graph.nodes) == 2
