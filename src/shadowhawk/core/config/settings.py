"""
Configuration settings for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv()


@dataclass
class MLConfig:
    """Machine learning configuration."""
    model_dir: str = field(default="models")
    batch_size: int = field(default=32)
    learning_rate: float = field(default=0.001)
    max_epochs: int = field(default=100)
    early_stopping_patience: int = field(default=10)
    validation_split: float = field(default=0.2)
    random_seed: int = field(default=42)
    device: str = field(default="auto")
    
    def __post_init__(self):
        if self.device == "auto":
            import torch
            self.device = "cuda" if torch.cuda.is_available() else "cpu"


@dataclass
class ExternalAPIConfig:
    """External API configuration."""
    nvd_api_key: Optional[str] = field(default=None)
    nvd_base_url: str = field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    mitre_attack_url: str = field(default="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    epss_base_url: str = field(default="https://api.first.org/data/v1/epss")
    exploitdb_url: str = field(default="https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv")
    rate_limit_per_second: int = field(default=10)
    request_timeout: int = field(default=30)
    cache_ttl: int = field(default=3600)
    
    def __post_init__(self):
        self.nvd_api_key = os.getenv("NVD_API_KEY", self.nvd_api_key)


@dataclass
class DatabaseConfig:
    """Database configuration."""
    url: str = field(default="sqlite:///shadowhawk.db")
    pool_size: int = field(default=10)
    max_overflow: int = field(default=20)
    pool_timeout: int = field(default=30)
    echo: bool = field(default=False)


@dataclass
class Settings:
    """Application settings."""
    app_name: str = "ShadowHawk Platform"
    version: str = "2.0.0"
    debug: bool = field(default=False)
    
    ml: MLConfig = field(default_factory=MLConfig)
    external_api: ExternalAPIConfig = field(default_factory=ExternalAPIConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    
    # Logging
    log_level: str = field(default="INFO")
    log_format: str = field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    # Feature flags
    enable_continuous_learning: bool = field(default=True)
    enable_threat_intelligence: bool = field(default=True)
    confidence_threshold: float = field(default=0.75)
    
    def __post_init__(self):
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", self.log_level)


# Global settings instance
settings = Settings()
