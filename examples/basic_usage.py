"""
Basic Usage Example
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License

Demonstrates basic usage of the ShadowHawk AI Analysis Engine.
"""

import asyncio
import os
from dotenv import load_dotenv

from shadowhawk.application.engines.ai_analysis import AIAnalysisEngine
from shadowhawk.infrastructure.ai.llm_client import LLMClient, LLMProvider


async def main() -> None:
    """Run basic AI analysis examples"""
    
    # Load environment variables
    load_dotenv()
    
    # Verify API keys are set
    if not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: No API keys found!")
        print("Please set OPENAI_API_KEY or ANTHROPIC_API_KEY in your .env file")
        return
    
    print("=" * 80)
    print("ShadowHawk AI Analysis Engine - Basic Usage Example")
    print("=" * 80)
    print()
    
    # Initialize the AI engine
    print("Initializing AI Analysis Engine...")
    engine = AIAnalysisEngine()
    print(f"✓ Using {engine.llm.provider.value} with model {engine.llm.model}")
    print(f"✓ Cache enabled: {engine.cache.enabled}")
    print()
    
    # Example 1: Threat Analysis
    print("-" * 80)
    print("Example 1: Threat Analysis")
    print("-" * 80)
    
    threat_result = await engine.analyze_threat(
        threat_id="CVE-2024-DEMO",
        threat_type="SQL Injection",
        severity="Critical",
        affected_systems="Production Web Application",
        threat_details=(
            "An unauthenticated SQL injection vulnerability was discovered in the "
            "user login form. The vulnerability allows attackers to bypass authentication "
            "and execute arbitrary SQL commands against the backend database."
        ),
    )
    
    print(f"Threat ID: {threat_result.threat_id}")
    print(f"Confidence Score: {threat_result.confidence_score}")
    print(f"\nExecutive Summary:")
    print(threat_result.executive_summary[:200] + "...")
    print(f"\nImmediate Actions: {len(threat_result.immediate_actions)} identified")
    print()
    
    # Example 2: MITRE ATT&CK Context
    print("-" * 80)
    print("Example 2: MITRE ATT&CK Context")
    print("-" * 80)
    
    mitre_result = await engine.get_mitre_context(
        finding_description="Suspicious PowerShell execution detected",
        observed_behaviors="Base64 encoded commands, network connections to external IP",
        affected_systems="Windows 10 workstations in marketing department",
        indicators="powershell.exe -enc flag, connection to 203.0.113.42",
    )
    
    print(f"Tactics: {', '.join(mitre_result.tactics[:3])}")
    print(f"Techniques: {', '.join(mitre_result.techniques[:3])}")
    print(f"Detection Strategies: {len(mitre_result.detection_strategies)} identified")
    print(f"Mitigation Techniques: {len(mitre_result.mitigation_techniques)} identified")
    print()
    
    # Example 3: Attack Path Analysis
    print("-" * 80)
    print("Example 3: Attack Path Analysis")
    print("-" * 80)
    
    attack_path_result = await engine.analyze_attack_path(
        entry_point="Phishing email with malicious Excel attachment",
        target_asset="Financial database containing payment card data",
        vulnerabilities="Unpatched Windows servers, weak domain passwords, macro execution enabled",
        security_controls="Windows Defender, network firewall, email gateway",
        network_topology="Flat network with limited segmentation, DMZ for web servers",
    )
    
    print(f"Attack Scenarios: {len(attack_path_result.attack_scenarios)} identified")
    print(f"Detection Opportunities: {len(attack_path_result.detection_opportunities)}")
    print(f"Defensive Recommendations: {len(attack_path_result.defensive_recommendations)}")
    print()
    
    # Display statistics
    print("-" * 80)
    print("Statistics")
    print("-" * 80)
    
    stats = engine.get_stats()
    print(f"LLM Requests: {stats['llm']['requests']}")
    print(f"Total Tokens: {stats['llm']['total_tokens']}")
    print(f"Total Cost: ${stats['llm']['total_cost']:.4f}")
    print(f"Cache Hit Rate: {stats['cache']['hit_rate_percent']:.1f}%")
    print()
    
    print("=" * 80)
    print("Example completed successfully!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
