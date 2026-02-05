"""
Metrics and monitoring utilities for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Optional

from prometheus_client import Counter, Gauge, Histogram, Info

# Model metrics
model_prediction_time = Histogram(
    "model_prediction_duration_seconds",
    "Time spent on model predictions",
    ["model_name"]
)

model_predictions_total = Counter(
    "model_predictions_total",
    "Total number of predictions",
    ["model_name", "status"]
)

model_confidence = Histogram(
    "model_confidence_score",
    "Distribution of confidence scores",
    ["model_name"]
)

# System metrics
api_requests_total = Counter(
    "external_api_requests_total",
    "Total external API requests",
    ["api_name", "status"]
)

api_request_duration = Histogram(
    "external_api_request_duration_seconds",
    "External API request duration",
    ["api_name"]
)

# Application metrics
active_threats = Gauge(
    "shadowhawk_active_threats",
    "Number of currently active threats"
)

risk_score_avg = Gauge(
    "shadowhawk_risk_score_average",
    "Average risk score across all entities"
)

engine_processing_time = Histogram(
    "engine_processing_duration_seconds",
    "Time spent processing by each engine",
    ["engine_name"]
)


@contextmanager
def timed_prediction(model_name: str):
    """Context manager for timing model predictions."""
    start_time = time.time()
    try:
        yield
        status = "success"
    except Exception:
        status = "error"
        raise
    finally:
        duration = time.time() - start_time
        model_prediction_time.labels(model_name=model_name).observe(duration)
        model_predictions_total.labels(model_name=model_name, status=status).inc()


@contextmanager
def timed_api_call(api_name: str):
    """Context manager for timing API calls."""
    start_time = time.time()
    try:
        yield
        status = "success"
    except Exception:
        status = "error"
        raise
    finally:
        duration = time.time() - start_time
        api_request_duration.labels(api_name=api_name).observe(duration)
        api_requests_total.labels(api_name=api_name, status=status).inc()


def record_confidence(model_name: str, score: float) -> None:
    """Record a confidence score."""
    model_confidence.labels(model_name=model_name).observe(score)


class PerformanceTracker:
    """Track performance metrics for ML models."""
    
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.metrics: Dict[str, Any] = {
            "total_predictions": 0,
            "total_time": 0.0,
            "errors": 0,
        }
    
    def record_prediction(self, duration: float, confidence: float, error: bool = False) -> None:
        """Record a prediction metric."""
        self.metrics["total_predictions"] += 1
        self.metrics["total_time"] += duration
        if error:
            self.metrics["errors"] += 1
        
        # Update Prometheus metrics
        model_prediction_time.labels(model_name=self.model_name).observe(duration)
        model_confidence.labels(model_name=self.model_name).observe(confidence)
        status = "error" if error else "success"
        model_predictions_total.labels(
            model_name=self.model_name, status=status
        ).inc()
    
    def get_average_latency(self) -> float:
        """Get average prediction latency."""
        if self.metrics["total_predictions"] == 0:
            return 0.0
        return self.metrics["total_time"] / self.metrics["total_predictions"]
    
    def get_error_rate(self) -> float:
        """Get error rate."""
        if self.metrics["total_predictions"] == 0:
            return 0.0
        return self.metrics["errors"] / self.metrics["total_predictions"]
