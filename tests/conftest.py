"""
Shared Test Fixtures
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License
"""

import pytest
import os
from typing import Generator


@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock environment variables for tests"""
    # Set dummy API keys to prevent real API calls
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-for-testing")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-for-testing")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("REDIS_CACHE_TTL", "3600")


@pytest.fixture
def sample_threat_data() -> dict:
    """Sample threat data for testing"""
    return {
        "threat_id": "CVE-2024-TEST",
        "threat_type": "SQL Injection",
        "severity": "Critical",
        "affected_systems": "Web Application",
        "threat_details": "SQL injection in login form allows database access",
    }


@pytest.fixture
def sample_findings() -> list:
    """Sample security findings for testing"""
    return [
        {
            "id": "VULN-001",
            "severity": "critical",
            "type": "SQL Injection",
            "description": "Critical SQL injection vulnerability",
        },
        {
            "id": "VULN-002",
            "severity": "high",
            "type": "XSS",
            "description": "Cross-site scripting vulnerability",
        },
        {
            "id": "VULN-003",
            "severity": "medium",
            "type": "CSRF",
            "description": "Cross-site request forgery",
        },
    ]


@pytest.fixture
def sample_llm_response() -> dict:
    """Sample LLM response for testing"""
    return {
        "content": "This is a test response from the LLM.",
        "provider": "openai",
        "model": "gpt-4-turbo-preview",
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "cost": 0.0025,
        "timestamp": "2024-02-05T12:00:00",
    }
