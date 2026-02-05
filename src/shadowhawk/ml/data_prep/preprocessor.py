"""
Data preprocessing utilities for ShadowHawk ML models.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import re
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler

from shadowhawk.core.utils.validation import sanitize_input


class DataPreprocessor:
    """
    Preprocessor for preparing security data for ML models.
    
    Handles feature extraction, normalization, and encoding of
    various security event data types.
    """
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95
        )
        self.is_fitted = False
    
    def extract_numeric_features(self, event: Dict) -> np.ndarray:
        """
        Extract numeric features from a security event.
        
        Expected event fields:
        - severity: int (1-10)
        - confidence: float (0-1)
        - timestamp: timestamp
        - source_reputation: float (0-1)
        - target_criticality: float (0-1)
        """
        features = []
        
        # Severity (normalize to 0-1)
        severity = event.get("severity", 5)
        features.append(severity / 10.0)
        
        # Confidence
        confidence = event.get("confidence", 0.5)
        features.append(confidence)
        
        # Time-based features
        timestamp = pd.to_datetime(event.get("timestamp", pd.Timestamp.now()))
        features.append(timestamp.hour / 24.0)  # Hour of day
        features.append(timestamp.dayofweek / 7.0)  # Day of week
        
        # Source reputation
        source_rep = event.get("source_reputation", 0.5)
        features.append(source_rep)
        
        # Target criticality
        target_crit = event.get("target_criticality", 0.5)
        features.append(target_crit)
        
        # Event type encoding (categorical)
        event_type = event.get("event_type", "unknown")
        type_encoded = self._encode_event_type(event_type)
        features.extend(type_encoded)
        
        return np.array(features)
    
    def _encode_event_type(self, event_type: str) -> List[float]:
        """One-hot encode event type."""
        event_types = [
            "network", "endpoint", "authentication", "file", 
            "process", "registry", "unknown"
        ]
        encoding = [0.0] * len(event_types)
        
        event_type = event_type.lower()
        if event_type in event_types:
            encoding[event_types.index(event_type)] = 1.0
        else:
            encoding[-1] = 1.0  # unknown
        
        return encoding
    
    def extract_risk_features(self, vulnerability: Dict) -> np.ndarray:
        """
        Extract risk-related features from vulnerability data.
        
        Expected fields:
        - cvss_score: float (0-10)
        - epss_score: float (0-1)
        - asset_criticality: float (0-1)
        - exploit_maturity: float (0-1)
        - threat_actor_capability: float (0-1)
        - exposure_level: float (0-1)
        - mitigation_effectiveness: float (0-1)
        - data_sensitivity: float (0-1)
        """
        features = [
            vulnerability.get("cvss_score", 5.0) / 10.0,
            vulnerability.get("epss_score", 0.5),
            vulnerability.get("asset_criticality", 0.5),
            vulnerability.get("exploit_maturity", 0.5),
            vulnerability.get("threat_actor_capability", 0.5),
            vulnerability.get("exposure_level", 0.5),
            vulnerability.get("mitigation_effectiveness", 0.5),
            vulnerability.get("data_sensitivity", 0.5),
        ]
        
        return np.array(features)
    
    def preprocess_text(self, text: str) -> str:
        """Preprocess text for NLP models."""
        text = sanitize_input(text)
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep spaces
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def extract_text_features(self, texts: List[str]) -> np.ndarray:
        """Extract TF-IDF features from text."""
        processed_texts = [self.preprocess_text(t) for t in texts]
        
        if not self.is_fitted:
            features = self.text_vectorizer.fit_transform(processed_texts)
        else:
            features = self.text_vectorizer.transform(processed_texts)
        
        return features.toarray()
    
    def prepare_training_data(
        self,
        events: List[Dict],
        labels: Optional[List] = None
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Prepare training data from a list of events.
        
        Returns:
            Tuple of (feature_matrix, label_array)
        """
        features = []
        for event in events:
            feat = self.extract_numeric_features(event)
            features.append(feat)
        
        X = np.array(features)
        
        y = None
        if labels:
            y = np.array(labels)
        
        self.is_fitted = True
        return X, y
    
    def normalize_features(self, X: np.ndarray) -> np.ndarray:
        """Normalize feature matrix."""
        if not self.is_fitted:
            X_scaled = self.scaler.fit_transform(X)
            self.is_fitted = True
        else:
            X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def create_correlation_features(
        self,
        events: List[Dict]
    ) -> Dict[str, np.ndarray]:
        """
        Create feature vectors for correlation analysis.
        
        Returns dictionary mapping event IDs to feature vectors.
        """
        features = {}
        
        for event in events:
            event_id = event.get("id", str(hash(str(event))))
            
            # Combine multiple feature types
            numeric_feat = self.extract_numeric_features(event)
            
            # Add temporal features
            timestamp = pd.to_datetime(event.get("timestamp", pd.Timestamp.now()))
            temporal_feat = np.array([
                timestamp.timestamp(),  # Unix timestamp
                timestamp.hour,
                timestamp.dayofweek,
            ])
            
            # Add entity features (IP, user, etc.)
            source_ip = self._encode_ip(event.get("source_ip", "0.0.0.0"))
            dest_ip = self._encode_ip(event.get("dest_ip", "0.0.0.0"))
            
            # Combine all features
            combined = np.concatenate([
                numeric_feat,
                temporal_feat,
                source_ip,
                dest_ip
            ])
            
            features[event_id] = combined
        
        return features
    
    def _encode_ip(self, ip: str) -> np.ndarray:
        """Encode IP address to numeric features."""
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return np.array([int(p) / 255.0 for p in parts])
        except ValueError:
            pass
        
        return np.array([0.0, 0.0, 0.0, 0.0])
    
    def encode_labels(self, labels: List[str]) -> np.ndarray:
        """Encode string labels to numeric."""
        if not self.is_fitted:
            encoded = self.label_encoder.fit_transform(labels)
            self.is_fitted = True
        else:
            encoded = self.label_encoder.transform(labels)
        
        return encoded
    
    def decode_labels(self, encoded: np.ndarray) -> List[str]:
        """Decode numeric labels to strings."""
        return self.label_encoder.inverse_transform(encoded)
