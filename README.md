# ShadowHawk Platform

ML-Powered Cybersecurity Threat Intelligence Platform

## Overview

ShadowHawk Platform is an intelligent cybersecurity threat detection and analysis system powered by machine learning. It provides comprehensive threat modeling, detection, correlation, and risk assessment capabilities.

## Features

### ML-Powered Engines

- **Threat Modeling Engine**: Graph-based attack surface analysis with ML-powered scenario generation
- **Detection Engine**: Anomaly detection and behavioral analysis using ensemble ML models
- **MITRE ATT&CK Mapping Engine**: NLP-based technique extraction and mapping
- **Correlation Engine**: Graph-based event correlation and campaign detection
- **Risk Scoring Engine**: Dynamic risk modeling with exploitability prediction

### External API Integrations

- **NVD (National Vulnerability Database)**: CVE data and vulnerability information
- **MITRE ATT&CK**: Threat intelligence and technique framework
- **EPSS (Exploit Prediction Scoring System)**: Exploit probability scoring
- **ExploitDB**: Exploit information and searchable database

### ML Models

- **AnomalyDetector**: Ensemble of Isolation Forest and Local Outlier Factor
- **ThreatClassifier**: Multi-class classifier using Random Forest, Gradient Boosting, and Logistic Regression
- **RiskPredictor**: Ensemble regressor for dynamic risk scoring
- **TechniqueExtractor**: NLP-based MITRE ATT&CK technique extraction
- **CorrelationModel**: Graph-based correlation with DBSCAN clustering

## Installation

```bash
# Clone the repository
git clone https://github.com/shadowhawk/platform.git
cd platform

# Install dependencies
pip install -e ".[dev]"
```

## Quick Start

```python
from shadowhawk.application.engines import (
    ThreatModelingEngine,
    DetectionEngine,
    MitreMappingEngine,
    CorrelationEngine,
    RiskScoringEngine,
)
from shadowhawk.ml.inference.engine import InferenceEngine

# Initialize engines
threat_modeler = ThreatModelingEngine()
detector = DetectionEngine()
mitre_mapper = MitreMappingEngine()
correlator = CorrelationEngine()
risk_scorer = RiskScoringEngine()
inference = InferenceEngine()

# Analyze a security event
event = {
    "id": "evt_001",
    "type": "network",
    "severity": 8,
    "description": "Suspicious outbound connection detected",
    "source_ip": "192.168.1.100",
}

detection_result = detector.analyze_event(event)
mitre_mapping = mitre_mapper.map_event(event)

# Perform comprehensive analysis
import numpy as np
features = np.random.rand(10)
analysis = inference.analyze_threat(features, event["description"], event["id"])
```

## Configuration

Set environment variables for external API access:

```bash
export NVD_API_KEY="your_nvd_api_key"
export DEBUG="false"
export LOG_LEVEL="INFO"
```

## Testing

```bash
# Run all tests
pytest

# Run unit tests only
pytest tests/unit/

# Run integration tests only
pytest tests/integration/

# Run with coverage
pytest --cov=src/shadowhawk --cov-report=html
```

## Project Structure

```
shadowhawk/
├── core/                   # Core utilities and configuration
│   ├── config/            # Configuration management
│   └── utils/             # Validation, metrics, helpers
├── ml/                     # Machine learning components
│   ├── models/            # ML models (anomaly, classification, etc.)
│   ├── training/          # Training pipelines
│   ├── inference/         # Inference engine
│   └── data_prep/         # Data preprocessing
├── application/            # Application layer
│   └── engines/           # Business logic engines
└── infrastructure/         # External integrations
    └── external/          # API clients
```

## License

MIT License - see LICENSE file for details

## Attribution

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
