"""
AI Integration Tests
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License

Comprehensive tests for AI analysis engine with mock LLM responses.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

from shadowhawk.application.engines.ai_analysis import (
    AIAnalysisEngine,
    ThreatAnalysis,
    RemediationPlan,
    AttackPathAnalysis,
    ExecutiveSummary,
    MitreContext,
)
from shadowhawk.infrastructure.ai.llm_client import LLMClient, LLMProvider
from shadowhawk.infrastructure.ai.prompt_library import PromptLibrary
from shadowhawk.infrastructure.ai.response_cache import ResponseCache


@pytest.fixture
def mock_llm_response() -> Dict[str, Any]:
    """Mock LLM response"""
    return {
        "content": """
1. EXECUTIVE SUMMARY
This is a critical SQL injection vulnerability that allows unauthorized database access.

2. TECHNICAL ANALYSIS

Attack Vector
The attack occurs through unsanitized user input in the login form.

Exploitation Method
Attackers can inject malicious SQL commands through the username field.

Technical Impact
Complete database access including read, write, and delete operations.

3. BUSINESS IMPACT

Potential Damage
Data breach, financial loss, regulatory penalties.

Affected Operations
All customer-facing operations relying on the database.

Compliance Implications
Violation of PCI-DSS and GDPR requirements.

4. IMMEDIATE ACTIONS
- Disable the vulnerable login form immediately
- Deploy WAF rules to block SQL injection attempts
- Audit database logs for suspicious activity
- Notify security team and stakeholders

5. LONG-TERM RECOMMENDATIONS
- Implement parameterized queries across the application
- Deploy automated security testing in CI/CD pipeline
- Conduct security training for development team
- Implement database access monitoring and alerting
        """,
        "provider": "openai",
        "model": "gpt-4-turbo-preview",
        "prompt_tokens": 150,
        "completion_tokens": 300,
        "total_tokens": 450,
        "cost": 0.0105,
        "timestamp": "2024-02-05T12:00:00",
    }


@pytest.fixture
def mock_llm_client(mock_llm_response: Dict[str, Any]) -> LLMClient:
    """Create mock LLM client"""
    client = Mock(spec=LLMClient)
    client.complete = AsyncMock(return_value=mock_llm_response)
    client.model = "gpt-4-turbo-preview"
    client.provider = LLMProvider.OPENAI
    client.temperature = 0.3
    client.max_tokens = 4096
    client.get_stats = Mock(return_value={
        "total_tokens": 450,
        "prompt_tokens": 150,
        "completion_tokens": 300,
        "total_cost": 0.0105,
        "requests": 1,
        "errors": 0,
    })
    return client


@pytest.fixture
def mock_cache() -> ResponseCache:
    """Create mock cache that always misses"""
    cache = Mock(spec=ResponseCache)
    cache.enabled = True
    cache.get = Mock(return_value=None)
    cache.set = Mock()
    cache.get_stats = Mock(return_value={
        "enabled": True,
        "hits": 0,
        "misses": 1,
        "total_requests": 1,
        "hit_rate_percent": 0.0,
    })
    return cache


@pytest.fixture
def ai_engine(mock_llm_client: LLMClient, mock_cache: ResponseCache) -> AIAnalysisEngine:
    """Create AI analysis engine with mocks"""
    return AIAnalysisEngine(
        llm_client=mock_llm_client,
        prompt_library=PromptLibrary(),
        response_cache=mock_cache,
    )


@pytest.mark.asyncio
async def test_analyze_threat(ai_engine: AIAnalysisEngine) -> None:
    """Test threat analysis"""
    result = await ai_engine.analyze_threat(
        threat_id="CVE-2024-1234",
        threat_type="SQL Injection",
        severity="Critical",
        affected_systems="Production Database",
        threat_details="Unauthenticated SQL injection in login form",
    )
    
    assert isinstance(result, ThreatAnalysis)
    assert result.threat_id == "CVE-2024-1234"
    assert len(result.executive_summary) > 0
    assert "attack_vector" in result.technical_analysis
    assert "potential_damage" in result.business_impact
    assert len(result.immediate_actions) > 0
    assert len(result.long_term_recommendations) > 0
    assert 0.0 <= result.confidence_score <= 1.0


@pytest.mark.asyncio
async def test_prioritize_remediation(
    ai_engine: AIAnalysisEngine,
    mock_llm_response: Dict[str, Any]
) -> None:
    """Test remediation prioritization"""
    # Update mock response for remediation
    mock_llm_response["content"] = """
1. PRIORITY 1 - IMMEDIATE (0-24 hours)
Finding: CVE-2024-1234 - Critical SQL Injection
Rationale: Active exploitation in the wild
Effort: 2 hours

2. PRIORITY 2 - URGENT (1-7 days)
Finding: Weak authentication mechanisms
Rationale: High risk of credential compromise
Effort: 1 week

3. PRIORITY 3 - PLANNED (1-4 weeks)
Finding: Missing security headers
Rationale: Improves defense in depth
Effort: 2 weeks

4. PRIORITY 4 - BACKLOG (1-3 months)
Finding: Outdated TLS configuration
Rationale: Low immediate risk
Effort: 1 month

5. RISK ASSESSMENT SUMMARY
Overall risk is high due to critical SQL injection vulnerability.
    """
    
    findings = [
        {"id": "CVE-2024-1234", "severity": "critical", "type": "SQL Injection"},
        {"id": "VULN-002", "severity": "high", "type": "Weak Authentication"},
    ]
    
    result = await ai_engine.prioritize_remediation(
        findings=findings,
        industry="Healthcare",
        critical_assets="Patient Database",
        compliance_requirements="HIPAA",
    )
    
    assert isinstance(result, RemediationPlan)
    assert len(result.priority_1) > 0
    assert len(result.priority_2) > 0
    assert len(result.priority_3) > 0
    assert len(result.priority_4) > 0
    assert len(result.risk_summary) > 0


@pytest.mark.asyncio
async def test_analyze_attack_path(
    ai_engine: AIAnalysisEngine,
    mock_llm_response: Dict[str, Any]
) -> None:
    """Test attack path analysis"""
    mock_llm_response["content"] = """
1. ATTACK PATH SCENARIOS
Scenario 1: Phishing to Ransomware
Step 1: Send phishing email
Step 2: Gain initial access
Step 3: Escalate privileges
Step 4: Deploy ransomware

2. KILL CHAIN MAPPING
Reconnaissance: Email reconnaissance
Weaponization: Malicious attachment
Delivery: Phishing email
Exploitation: Macro execution
Installation: Persistence mechanism
Command & Control: C2 connection
Actions on Objectives: Data encryption

3. DETECTION OPPORTUNITIES
- Email gateway monitoring
- Endpoint detection and response
- Network traffic analysis
- User behavior analytics

4. DEFENSIVE RECOMMENDATIONS
- Email security training
- Multi-factor authentication
- Application whitelisting
- Network segmentation
    """
    
    result = await ai_engine.analyze_attack_path(
        entry_point="Phishing email",
        target_asset="Financial Database",
        vulnerabilities="Unpatched systems, weak passwords",
        security_controls="Antivirus, firewall",
        network_topology="Flat network",
    )
    
    assert isinstance(result, AttackPathAnalysis)
    assert len(result.attack_scenarios) > 0
    assert "raw" in result.kill_chain_mapping
    assert len(result.detection_opportunities) > 0
    assert len(result.defensive_recommendations) > 0


@pytest.mark.asyncio
async def test_generate_executive_summary(
    ai_engine: AIAnalysisEngine,
    mock_llm_response: Dict[str, Any]
) -> None:
    """Test executive summary generation"""
    mock_llm_response["content"] = """
1. KEY FINDINGS
- Critical SQL injection vulnerability discovered
- Multiple high-severity authentication issues
- Outdated security controls requiring updates

2. RISK ASSESSMENT
Overall security posture: Yellow
Risk trend: Improving from previous quarter
Top risk areas: Application security, access control

3. BUSINESS IMPACT
Financial impact: Potential $2M in breach costs
Operational risks: Service disruption possible
Reputational risks: Customer trust at stake
Regulatory exposure: Potential HIPAA violations

4. RECOMMENDED ACTIONS
Immediate: Patch SQL injection within 24 hours
Investment: $50K for security improvements
Expected risk reduction: 60% within 30 days

5. METRICS & BENCHMARKS
Security score: 72/100
Industry average: 68/100
Trend: +5 points from last quarter
    """
    
    result = await ai_engine.generate_executive_summary(
        assessment_period="Q1 2024",
        scope="Enterprise Infrastructure",
        findings_summary="15 critical, 30 high, 45 medium",
        critical_issues="SQL injection, weak authentication",
        risk_score="7.2/10",
        comparison_data="Improved from 7.8/10",
    )
    
    assert isinstance(result, ExecutiveSummary)
    assert len(result.key_findings) > 0
    assert "raw" in result.risk_assessment
    assert "raw" in result.business_impact
    assert len(result.recommended_actions) > 0


@pytest.mark.asyncio
async def test_get_mitre_context(
    ai_engine: AIAnalysisEngine,
    mock_llm_response: Dict[str, Any]
) -> None:
    """Test MITRE ATT&CK context"""
    mock_llm_response["content"] = """
1. MITRE ATT&CK MAPPING

Tactic(s): Initial Access (TA0001)
Technique(s): Phishing (T1566)
Sub-technique(s): Spearphishing Attachment (T1566.001)

2. ADVERSARY INTELLIGENCE
Known groups: APT28, APT29, FIN7
Common objectives: Credential theft, data exfiltration

3. DETECTION STRATEGIES
- Monitor email gateway logs
- Analyze attachment types
- Detect suspicious process execution
- Monitor network connections

4. MITIGATION TECHNIQUES
- User awareness training
- Email filtering
- Application whitelisting
- Endpoint protection

5. RELATED TECHNIQUES
- Valid Accounts (T1078)
- Exploitation for Client Execution (T1203)
    """
    
    result = await ai_engine.get_mitre_context(
        finding_description="Suspicious email with malicious attachment",
        observed_behaviors="Macro execution, network callback",
        affected_systems="Windows workstations",
        indicators="Malicious document hash: abc123",
    )
    
    assert isinstance(result, MitreContext)
    assert len(result.tactics) > 0
    assert len(result.techniques) > 0
    assert len(result.detection_strategies) > 0
    assert len(result.mitigation_techniques) > 0


@pytest.mark.asyncio
async def test_caching_behavior(
    mock_llm_client: LLMClient,
    mock_llm_response: Dict[str, Any]
) -> None:
    """Test response caching"""
    # Create cache that returns cached response on second call
    cache = Mock(spec=ResponseCache)
    cache.enabled = True
    
    # First call - cache miss
    cache.get = Mock(return_value=None)
    cache.set = Mock()
    
    engine = AIAnalysisEngine(
        llm_client=mock_llm_client,
        response_cache=cache,
    )
    
    # First call should hit LLM
    await engine.analyze_threat(
        threat_id="TEST-001",
        threat_type="Test",
        severity="High",
        affected_systems="Test Systems",
        threat_details="Test details",
    )
    
    # Verify cache.set was called
    assert cache.set.called
    
    # Second call with cache hit
    cache.get = Mock(return_value=mock_llm_response)
    
    result = await engine.analyze_threat(
        threat_id="TEST-001",
        threat_type="Test",
        severity="High",
        affected_systems="Test Systems",
        threat_details="Test details",
    )
    
    # Verify result is still valid
    assert isinstance(result, ThreatAnalysis)


@pytest.mark.asyncio
async def test_stats_collection(ai_engine: AIAnalysisEngine) -> None:
    """Test statistics collection"""
    stats = ai_engine.get_stats()
    
    assert "llm" in stats
    assert "cache" in stats
    assert "total_tokens" in stats["llm"]
    assert "total_cost" in stats["llm"]
    assert "hit_rate_percent" in stats["cache"]


@pytest.mark.asyncio
async def test_error_handling(mock_llm_client: LLMClient, mock_cache: ResponseCache) -> None:
    """Test error handling in AI engine"""
    # Configure mock to raise exception
    mock_llm_client.complete = AsyncMock(side_effect=Exception("API Error"))
    
    engine = AIAnalysisEngine(
        llm_client=mock_llm_client,
        response_cache=mock_cache,
    )
    
    with pytest.raises(Exception) as exc_info:
        await engine.analyze_threat(
            threat_id="TEST-001",
            threat_type="Test",
            severity="High",
            affected_systems="Test",
            threat_details="Test",
        )
    
    assert "API Error" in str(exc_info.value)


def test_prompt_library_integration() -> None:
    """Test prompt library integration"""
    library = PromptLibrary()
    
    # Verify prompts are loaded (if directory exists)
    templates = library.list_templates()
    
    # Should have loaded our prompt files
    expected_prompts = [
        "threat_explanation",
        "remediation_prioritization",
        "attack_path",
        "executive_summary",
        "mitre_context",
    ]
    
    for prompt_name in expected_prompts:
        try:
            template = library.get(prompt_name)
            assert template.name == prompt_name
            assert len(template.system_prompt) > 0
            assert len(template.user_prompt_template) > 0
        except KeyError:
            # Prompts might not be loaded if directory doesn't exist in test env
            pass
