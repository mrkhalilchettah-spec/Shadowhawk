"""
Continuous learning and model retraining pipeline.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

from shadowhawk.core.config.settings import settings
from shadowhawk.ml.models.anomaly_detector import AnomalyDetector
from shadowhawk.ml.models.correlation_model import CorrelationModel
from shadowhawk.ml.models.risk_predictor import RiskPredictor
from shadowhawk.ml.models.technique_extractor import TechniqueExtractor
from shadowhawk.ml.models.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)


@dataclass
class TrainingResult:
    """Result of a model training run."""
    model_name: str
    version: str
    timestamp: datetime
    metrics: Dict[str, Any]
    model_path: Path
    status: str
    message: str


class ContinuousLearningPipeline:
    """
    Pipeline for continuous model training and retraining.
    
    Manages model versioning, training schedules, and performance monitoring.
    """
    
    def __init__(self, models_dir: Optional[Path] = None):
        self.models_dir = models_dir or Path(settings.ml.model_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.training_history: List[TrainingResult] = []
        self.performance_threshold = 0.75
        
        # Model registry
        self.model_registry: Dict[str, Dict] = {}
        self._load_registry()
    
    def _load_registry(self) -> None:
        """Load model registry from disk."""
        registry_path = self.models_dir / "registry.json"
        if registry_path.exists():
            with open(registry_path, "r") as f:
                self.model_registry = json.load(f)
    
    def _save_registry(self) -> None:
        """Save model registry to disk."""
        registry_path = self.models_dir / "registry.json"
        with open(registry_path, "w") as f:
            json.dump(self.model_registry, f, indent=2, default=str)
    
    def _generate_version(self, model_name: str) -> str:
        """Generate a new version string for a model."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{model_name}_{timestamp}"
    
    def train_anomaly_detector(
        self,
        X: np.ndarray,
        feature_names: Optional[List[str]] = None,
        force: bool = False
    ) -> TrainingResult:
        """Train and save the anomaly detection model."""
        model_name = "anomaly_detector"
        version = self._generate_version(model_name)
        
        try:
            # Split data
            X_train, X_val = train_test_split(
                X, test_size=settings.ml.validation_split, 
                random_state=settings.ml.random_seed
            )
            
            # Train model
            model = AnomalyDetector(random_state=settings.ml.random_seed)
            model.fit(X_train, feature_names=feature_names)
            
            # Validate
            predictions, confidences = model.predict(X_val, return_confidence=True)
            
            # Calculate metrics
            metrics = {
                "train_size": len(X_train),
                "val_size": len(X_val),
                "anomaly_rate": float(np.mean(predictions == -1)),
                "avg_confidence": float(np.mean(confidences)),
            }
            
            # Save model
            model_path = self.models_dir / f"{version}.pkl"
            model.save(model_path)
            
            # Update registry
            self.model_registry[model_name] = {
                "version": version,
                "path": str(model_path),
                "metrics": metrics,
                "timestamp": datetime.now().isoformat(),
            }
            self._save_registry()
            
            result = TrainingResult(
                model_name=model_name,
                version=version,
                timestamp=datetime.now(),
                metrics=metrics,
                model_path=model_path,
                status="success",
                message="Model trained successfully"
            )
        
        except Exception as e:
            result = TrainingResult(
                model_name=model_name,
                version=version,
                timestamp=datetime.now(),
                metrics={},
                model_path=Path(),
                status="error",
                message=str(e)
            )
            logger.error(f"Training failed for {model_name}: {e}")
        
        self.training_history.append(result)
        return result
    
    def train_threat_classifier(
        self,
        X_numeric: np.ndarray,
        y: np.ndarray,
        X_text: Optional[List[str]] = None,
        force: bool = False
    ) -> TrainingResult:
        """Train and save the threat classification model."""
        model_name = "threat_classifier"
        version = self._generate_version(model_name)
        
        try:
            # Split data
            indices = np.arange(len(y))
            train_idx, val_idx = train_test_split(
                indices, test_size=settings.ml.validation_split,
                random_state=settings.ml.random_seed, stratify=y
            )
            
            X_train, X_val = X_numeric[train_idx], X_numeric[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]
            X_text_train = [X_text[i] for i in train_idx] if X_text else None
            
            # Train model
            model = ThreatClassifier(
                use_text_features=X_text is not None,
                random_state=settings.ml.random_seed
            )
            model.fit(X_train, y_train, X_text_train)
            
            # Evaluate
            eval_metrics = model.evaluate(X_val, y_val)
            
            # Save model
            model_path = self.models_dir / f"{version}.pkl"
            model.save(model_path)
            
            metrics = {
                **eval_metrics,
                "train_size": len(train_idx),
                "val_size": len(val_idx),
            }
            
            # Update registry
            self.model_registry[model_name] = {
                "version": version,
                "path": str(model_path),
                "metrics": metrics,
                "timestamp": datetime.now().isoformat(),
            }
            self._save_registry()
            
            result = TrainingResult(
                model_name=model_name,
                version=version,
                timestamp=datetime.now(),
                metrics=metrics,
                model_path=model_path,
                status="success",
                message="Model trained successfully"
            )
        
        except Exception as e:
            result = TrainingResult(
                model_name=model_name,
                version=version,
                timestamp=datetime.now(),
                metrics={},
                model_path=Path(),
                status="error",
                message=str(e)
            )
            logger.error(f"Training failed for {model_name}: {e}")
        
        self.training_history.append(result)
        return result
    
    def train_risk_predictor(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[List[str]] = None,
        force: bool = False
    ) -> TrainingResult:
        """Train and save the risk prediction model."""
        model_name = "risk_predictor"
        version = self._generate_version(model_name)
        
        try:
            # Split data
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=settings.ml.validation_split,
                random_state=settings.ml.random_seed
            )
            
            # Train model
            model = RiskPredictor(random_state=settings.ml.random_seed)
            model.fit(X_train, y_train, feature_names=feature_names)
            
            # Evaluate
            eval_metrics = model.evaluate(X_val, y_val)
            
            # Save model
            model_path = self.models_dir / f"{version}.pkl"
            model.save(model_path)
            
            metrics = {
                **eval_metrics,
                "train_size": len(X_train),
                "val_size": len(X_val),
            }
            
            # Update registry
            self.model_registry[model_name] = {
                "version": version,
                "path": str(model_path),
                "metrics": metrics,
                "timestamp": datetime.now().isoformat(),
            }
            self._save_registry()
            
            result = TrainingResult(
                model_name=model_name,
                version=version,
                timestamp=datetime.now(),
                metrics=metrics,
                model_path=model_path,
                status="success",
                message="Model trained successfully"
            )
        
        except Exception as e:
            result = TrainingResult(
                model_name=model_name,
                version=version,
                timestamp=datetime.now(),
                metrics={},
                model_path=Path(),
                status="error",
                message=str(e)
            )
            logger.error(f"Training failed for {model_name}: {e}")
        
        self.training_history.append(result)
        return result
    
    def check_retraining_needed(self, model_name: str) -> bool:
        """Check if a model needs retraining based on age and performance."""
        if model_name not in self.model_registry:
            return True
        
        model_info = self.model_registry[model_name]
        last_trained = datetime.fromisoformat(model_info["timestamp"])
        
        # Check if older than 7 days
        age = datetime.now() - last_trained
        if age > timedelta(days=7):
            return True
        
        # Check performance metrics
        metrics = model_info.get("metrics", {})
        if "accuracy" in metrics and metrics["accuracy"] < self.performance_threshold:
            return True
        if "r2" in metrics and metrics["r2"] < self.performance_threshold:
            return True
        
        return False
    
    def get_best_model(self, model_name: str) -> Optional[Path]:
        """Get path to the best version of a model."""
        if model_name not in self.model_registry:
            return None
        
        return Path(self.model_registry[model_name]["path"])
    
    def list_models(self) -> Dict[str, List[Dict]]:
        """List all registered models and their versions."""
        return self.model_registry
    
    def get_training_history(self) -> List[TrainingResult]:
        """Get the training history."""
        return self.training_history
