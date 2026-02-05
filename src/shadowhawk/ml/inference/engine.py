"""
ML inference engine for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np

from shadowhawk.core.config.settings import settings
from shadowhawk.ml.models.anomaly_detector import AnomalyDetector
from shadowhawk.ml.models.correlation_model import CorrelationModel
from shadowhawk.ml.models.risk_predictor import RiskPredictor
from shadowhawk.ml.models.technique_extractor import TechniqueExtractor
from shadowhawk.ml.models.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)


class InferenceEngine:
    """
    Centralized inference engine for all ML models.
    
    Manages model loading, caching, and provides a unified interface
    for making predictions across all models.
    """
    
    def __init__(self, models_dir: Optional[Path] = None):
        self.models_dir = models_dir or Path(settings.ml.model_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Model cache
        self._anomaly_detector: Optional[AnomalyDetector] = None
        self._threat_classifier: Optional[ThreatClassifier] = None
        self._risk_predictor: Optional[RiskPredictor] = None
        self._technique_extractor: Optional[TechniqueExtractor] = None
        self._correlation_model: Optional[CorrelationModel] = None
        
        self._loaded_models: Dict[str, Any] = {}
    
    def load_anomaly_detector(self, model_path: Optional[Path] = None) -> AnomalyDetector:
        """Load or return cached anomaly detector."""
        if self._anomaly_detector is not None:
            return self._anomaly_detector
        
        if model_path and model_path.exists():
            self._anomaly_detector = AnomalyDetector.load(model_path)
        else:
            # Create default model
            self._anomaly_detector = AnomalyDetector(random_state=settings.ml.random_seed)
        
        self._loaded_models["anomaly_detector"] = self._anomaly_detector
        return self._anomaly_detector
    
    def load_threat_classifier(self, model_path: Optional[Path] = None) -> ThreatClassifier:
        """Load or return cached threat classifier."""
        if self._threat_classifier is not None:
            return self._threat_classifier
        
        if model_path and model_path.exists():
            self._threat_classifier = ThreatClassifier.load(model_path)
        else:
            self._threat_classifier = ThreatClassifier(
                use_text_features=True,
                random_state=settings.ml.random_seed
            )
        
        self._loaded_models["threat_classifier"] = self._threat_classifier
        return self._threat_classifier
    
    def load_risk_predictor(self, model_path: Optional[Path] = None) -> RiskPredictor:
        """Load or return cached risk predictor."""
        if self._risk_predictor is not None:
            return self._risk_predictor
        
        if model_path and model_path.exists():
            self._risk_predictor = RiskPredictor.load(model_path)
        else:
            self._risk_predictor = RiskPredictor(random_state=settings.ml.random_seed)
        
        self._loaded_models["risk_predictor"] = self._risk_predictor
        return self._risk_predictor
    
    def load_technique_extractor(
        self, 
        model_path: Optional[Path] = None
    ) -> TechniqueExtractor:
        """Load or return cached technique extractor."""
        if self._technique_extractor is not None:
            return self._technique_extractor
        
        if model_path and model_path.exists():
            self._technique_extractor = TechniqueExtractor.load(model_path)
        else:
            self._technique_extractor = TechniqueExtractor(
                use_pretrained=True
            )
        
        self._loaded_models["technique_extractor"] = self._technique_extractor
        return self._technique_extractor
    
    def load_correlation_model(self, model_path: Optional[Path] = None) -> CorrelationModel:
        """Load or return cached correlation model."""
        if self._correlation_model is not None:
            return self._correlation_model
        
        if model_path and model_path.exists():
            self._correlation_model = CorrelationModel.load(model_path)
        else:
            self._correlation_model = CorrelationModel()
        
        self._loaded_models["correlation_model"] = self._correlation_model
        return self._correlation_model
    
    def detect_anomalies(
        self, 
        features: np.ndarray,
        threshold: Optional[float] = None
    ) -> List[Dict]:
        """
        Detect anomalies in feature data.
        
        Args:
            features: Feature matrix
            threshold: Optional confidence threshold
        
        Returns:
            List of anomaly detections with confidence scores
        """
        model = self.load_anomaly_detector()
        
        if not model.is_fitted:
            logger.warning("Anomaly detector not fitted. Training on provided data.")
            model.fit(features)
        
        return model.detect_anomalies(features, threshold)
    
    def classify_threats(
        self,
        features: np.ndarray,
        descriptions: Optional[List[str]] = None,
        top_k: int = 3
    ) -> List[Dict]:
        """
        Classify threats from features and optional text descriptions.
        
        Args:
            features: Numeric feature matrix
            descriptions: Optional text descriptions
            top_k: Number of top predictions to return
        
        Returns:
            List of classification results
        """
        model = self.load_threat_classifier()
        return model.classify_threat(features, descriptions, top_k)
    
    def predict_risk(
        self,
        features: np.ndarray,
        context: Optional[List[Dict]] = None
    ) -> List[Dict]:
        """
        Predict risk scores from features.
        
        Args:
            features: Risk factor feature matrix
            context: Optional context for each prediction
        
        Returns:
            List of risk predictions
        """
        model = self.load_risk_predictor()
        
        if not model.is_fitted:
            logger.warning("Risk predictor not fitted.")
            return [{"error": "Model not trained"}]
        
        return model.predict_risk_with_details(features, context)
    
    def extract_techniques(
        self,
        text: str,
        min_confidence: Optional[float] = None
    ) -> List[Dict]:
        """
        Extract MITRE ATT&CK techniques from text.
        
        Args:
            text: Input text to analyze
            min_confidence: Minimum confidence threshold
        
        Returns:
            List of extracted techniques
        """
        model = self.load_technique_extractor()
        return model.extract_techniques(text, min_confidence)
    
    def correlate_events(
        self,
        event_features: Dict[str, np.ndarray],
        metadata: Optional[Dict[str, Dict]] = None
    ) -> List[Dict]:
        """
        Correlate security events and detect campaigns.
        
        Args:
            event_features: Dictionary mapping event IDs to feature vectors
            metadata: Optional metadata for each event
        
        Returns:
            List of detected campaigns
        """
        model = self.load_correlation_model()
        
        # Add events to graph
        for event_id, features in event_features.items():
            meta = metadata.get(event_id, {}) if metadata else {}
            model.add_event(event_id, features, meta)
        
        # Build correlation graph
        model.build_graph()
        
        # Detect campaigns
        return model.detect_campaigns()
    
    def analyze_threat(
        self,
        features: np.ndarray,
        description: Optional[str] = None,
        event_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive threat analysis using all models.
        
        Args:
            features: Feature vector for the threat
            description: Optional text description
            event_id: Optional event identifier
        
        Returns:
            Comprehensive analysis result
        """
        result = {
            "event_id": event_id,
            "timestamp": settings.ml.random_seed,
            "analysis": {}
        }
        
        # Anomaly detection
        try:
            anomaly_results = self.detect_anomalies(features.reshape(1, -1))
            result["analysis"]["anomaly"] = anomaly_results[0] if anomaly_results else None
        except Exception as e:
            result["analysis"]["anomaly"] = {"error": str(e)}
        
        # Threat classification
        try:
            classification = self.classify_threats(
                features.reshape(1, -1),
                [description] if description else None
            )
            result["analysis"]["classification"] = classification[0] if classification else None
        except Exception as e:
            result["analysis"]["classification"] = {"error": str(e)}
        
        # Risk prediction
        try:
            risk = self.predict_risk(features.reshape(1, -1))
            result["analysis"]["risk"] = risk[0] if risk else None
        except Exception as e:
            result["analysis"]["risk"] = {"error": str(e)}
        
        # Technique extraction
        if description:
            try:
                techniques = self.extract_techniques(description)
                result["analysis"]["techniques"] = techniques
            except Exception as e:
                result["analysis"]["techniques"] = {"error": str(e)}
        
        return result
    
    def get_model_status(self) -> Dict[str, Dict]:
        """Get status of all loaded models."""
        status = {}
        for name, model in self._loaded_models.items():
            status[name] = {
                "loaded": True,
                "is_fitted": getattr(model, "is_fitted", False),
                "type": type(model).__name__,
            }
        return status
    
    def clear_cache(self) -> None:
        """Clear the model cache."""
        self._anomaly_detector = None
        self._threat_classifier = None
        self._risk_predictor = None
        self._technique_extractor = None
        self._correlation_model = None
        self._loaded_models.clear()
