"""
Validation utilities for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import re
from typing import Any, Dict, List, Optional, Union

import numpy as np


def validate_confidence_score(score: float) -> float:
    """Validate and normalize confidence score."""
    if not isinstance(score, (int, float)):
        raise ValueError(f"Confidence score must be numeric, got {type(score)}")
    score = float(score)
    if not 0 <= score <= 1:
        raise ValueError(f"Confidence score must be between 0 and 1, got {score}")
    return score


def validate_probability(prob: float, name: str = "probability") -> float:
    """Validate a probability value."""
    if not isinstance(prob, (int, float)):
        raise ValueError(f"{name} must be numeric, got {type(prob)}")
    prob = float(prob)
    if not 0 <= prob <= 1:
        raise ValueError(f"{name} must be between 0 and 1, got {prob}")
    return prob


def sanitize_input(text: str) -> str:
    """Sanitize input text for ML processing."""
    if not isinstance(text, str):
        text = str(text)
    # Remove control characters except newlines and tabs
    text = "".join(char for char in text if ord(char) >= 32 or char in "\n\t")
    # Normalize whitespace
    text = " ".join(text.split())
    return text.strip()


def validate_feature_vector(features: np.ndarray, expected_dim: Optional[int] = None) -> np.ndarray:
    """Validate feature vector dimensions and values."""
    if not isinstance(features, np.ndarray):
        features = np.array(features)
    
    if features.ndim == 1:
        features = features.reshape(1, -1)
    
    if expected_dim and features.shape[1] != expected_dim:
        raise ValueError(
            f"Expected feature dimension {expected_dim}, got {features.shape[1]}"
        )
    
    # Check for NaN or Inf values
    if np.any(np.isnan(features)):
        raise ValueError("Feature vector contains NaN values")
    if np.any(np.isinf(features)):
        raise ValueError("Feature vector contains infinite values")
    
    return features


def extract_cve_id(text: str) -> Optional[str]:
    """Extract CVE ID from text."""
    pattern = r"CVE-\d{4}-\d{4,}"
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def extract_ip_address(text: str) -> List[str]:
    """Extract IP addresses from text."""
    pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    return re.findall(pattern, text)


def normalize_threat_name(name: str) -> str:
    """Normalize threat name for consistent processing."""
    name = sanitize_input(name)
    # Convert to lowercase and replace special chars with underscore
    name = re.sub(r"[^a-zA-Z0-9_\s]", "_", name.lower())
    name = re.sub(r"_+", "_", name)
    return name.strip("_")
