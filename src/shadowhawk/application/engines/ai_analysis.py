"""
ShadowHawk Platform - AI Analysis Engine

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import Dict, Any, List, Optional
import logging
import json

from ...domain.models.finding import Finding
from ...domain.models.threat import Threat
from ...domain.models.detection import Detection

logger = logging.getLogger(__name__)


class AIAnalysisEngine:
    """
    AI Analysis Engine for LLM-powered threat explanation and analysis.
    
    Provides structured threat explanations using large language models.
    """
    
    def __init__(self, api_key: Optional[str] = None, provider: str = "openai"):
        """
        Initialize the AI analysis engine.
        
        Args:
            api_key: API key for the LLM provider
            provider: LLM provider (openai, anthropic, etc.)
        """
        self.api_key = api_key
        self.provider = provider
        self.model = self._select_model()
    
    def _select_model(self) -> str:
        """Select the appropriate model based on provider."""
        models = {
            "openai": "gpt-4",
            "anthropic": "claude-3-opus-20240229",
        }
        return models.get(self.provider, "gpt-4")
    
    def explain_finding(self, finding: Finding) -> Dict[str, Any]:
        """
        Generate an AI-powered explanation for a finding.
        
        Args:
            finding: The finding to explain
            
        Returns:
            Structured explanation
        """
        prompt = self._create_finding_prompt(finding)
        
        explanation = {
            "summary": self._generate_summary(finding),
            "technical_details": self._analyze_technical_details(finding),
            "impact_assessment": self._assess_impact(finding),
            "remediation_guidance": self._generate_remediation(finding),
            "references": finding.references,
        }
        
        logger.info(f"Generated AI explanation for finding: {finding.title}")
        return explanation
    
    def _create_finding_prompt(self, finding: Finding) -> str:
        """Create a prompt for finding analysis."""
        return f"""
        Analyze the following security finding:
        
        Title: {finding.title}
        Severity: {finding.severity.value}
        Description: {finding.description}
        CVSS Score: {finding.cvss_score}
        CVE IDs: {', '.join(finding.cve_ids) if finding.cve_ids else 'None'}
        MITRE Techniques: {', '.join(finding.mitre_techniques) if finding.mitre_techniques else 'None'}
        
        Provide a detailed analysis including:
        1. Technical explanation
        2. Potential impact
        3. Attack scenarios
        4. Remediation recommendations
        """
    
    def _generate_summary(self, finding: Finding) -> str:
        """Generate a concise summary of the finding."""
        severity_descriptions = {
            "critical": "This is a critical security issue requiring immediate attention.",
            "high": "This is a high-severity security issue that should be addressed promptly.",
            "medium": "This is a medium-severity security issue that should be reviewed.",
            "low": "This is a low-severity security issue for future consideration.",
            "info": "This is an informational finding for awareness.",
        }
        
        summary = f"{finding.title}. "
        summary += severity_descriptions.get(finding.severity.value, "")
        
        if finding.cvss_score:
            summary += f" CVSS Score: {finding.cvss_score}."
        
        return summary
    
    def _analyze_technical_details(self, finding: Finding) -> Dict[str, Any]:
        """Analyze technical details of the finding."""
        details = {
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score,
            "cve_ids": finding.cve_ids,
            "mitre_attack": {
                "tactics": finding.mitre_tactics,
                "techniques": finding.mitre_techniques,
            },
        }
        
        if finding.evidence:
            details["evidence_count"] = len(finding.evidence)
            details["key_indicators"] = self._extract_key_indicators(finding.evidence)
        
        return details
    
    def _extract_key_indicators(self, evidence: List[Dict[str, Any]]) -> List[str]:
        """Extract key indicators from evidence."""
        indicators = []
        
        for item in evidence[:5]:
            if isinstance(item, dict):
                if "indicator" in item:
                    indicators.append(str(item["indicator"]))
                elif "value" in item:
                    indicators.append(str(item["value"]))
        
        return indicators
    
    def _assess_impact(self, finding: Finding) -> Dict[str, Any]:
        """Assess the impact of the finding."""
        impact_levels = {
            "critical": {
                "description": "Critical impact to confidentiality, integrity, or availability",
                "business_impact": "Severe disruption to business operations",
                "data_risk": "High risk of data breach or loss",
            },
            "high": {
                "description": "Significant impact to security posture",
                "business_impact": "Moderate disruption to business operations",
                "data_risk": "Elevated risk of unauthorized access",
            },
            "medium": {
                "description": "Moderate impact to specific systems or data",
                "business_impact": "Limited disruption to business operations",
                "data_risk": "Some risk of information disclosure",
            },
            "low": {
                "description": "Minor impact to security posture",
                "business_impact": "Minimal disruption to business operations",
                "data_risk": "Low risk of security compromise",
            },
            "info": {
                "description": "No direct security impact",
                "business_impact": "No business disruption",
                "data_risk": "Informational only",
            },
        }
        
        return impact_levels.get(finding.severity.value, impact_levels["medium"])
    
    def _generate_remediation(self, finding: Finding) -> List[str]:
        """Generate remediation guidance."""
        if finding.remediation:
            return [finding.remediation]
        
        generic_steps = [
            "Review the finding details and assess applicability to your environment",
            "Consult vendor security advisories for specific guidance",
            "Test remediation steps in a non-production environment",
            "Implement fixes with appropriate change management",
            "Verify the fix and re-test to confirm resolution",
        ]
        
        if finding.cve_ids:
            generic_steps.insert(1, "Apply security patches addressing the identified CVEs")
        
        return generic_steps
    
    def analyze_threat(self, threat: Threat) -> Dict[str, Any]:
        """
        Analyze a threat using AI.
        
        Args:
            threat: The threat to analyze
            
        Returns:
            Threat analysis
        """
        analysis = {
            "threat_summary": f"{threat.title}: {threat.description}",
            "stride_classification": [cat.value for cat in threat.stride_categories],
            "attack_scenarios": self._generate_attack_scenarios(threat),
            "mitigation_strategy": threat.mitigations,
            "priority": self._assess_threat_priority(threat),
        }
        
        logger.info(f"Generated AI analysis for threat: {threat.title}")
        return analysis
    
    def _generate_attack_scenarios(self, threat: Threat) -> List[str]:
        """Generate potential attack scenarios for a threat."""
        scenarios = []
        
        for stride_cat in threat.stride_categories:
            scenario_templates = {
                "spoofing": "An attacker could impersonate a legitimate user or system",
                "tampering": "An attacker could modify data or code without authorization",
                "repudiation": "A malicious actor could perform actions and deny responsibility",
                "information_disclosure": "Sensitive information could be exposed to unauthorized parties",
                "denial_of_service": "An attacker could disrupt service availability",
                "elevation_of_privilege": "An attacker could gain unauthorized elevated access",
            }
            
            scenario = scenario_templates.get(stride_cat.value)
            if scenario:
                scenarios.append(scenario)
        
        return scenarios
    
    def _assess_threat_priority(self, threat: Threat) -> str:
        """Assess the priority of addressing a threat."""
        impact_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        likelihood_weights = {"high": 3, "medium": 2, "low": 1}
        
        impact_weight = impact_weights.get(threat.impact, 2)
        likelihood_weight = likelihood_weights.get(threat.likelihood, 2)
        
        priority_score = impact_weight * likelihood_weight
        
        if priority_score >= 9:
            return "critical"
        elif priority_score >= 6:
            return "high"
        elif priority_score >= 3:
            return "medium"
        else:
            return "low"
    
    def generate_executive_summary(
        self,
        findings: List[Finding],
        threats: List[Threat],
        detections: List[Detection]
    ) -> Dict[str, Any]:
        """
        Generate an executive summary of security posture.
        
        Args:
            findings: List of findings
            threats: List of threats
            detections: List of detections
            
        Returns:
            Executive summary
        """
        critical_findings = [f for f in findings if f.severity.value == "critical"]
        high_findings = [f for f in findings if f.severity.value == "high"]
        
        summary = {
            "overview": self._create_overview(findings, threats, detections),
            "key_findings": {
                "total": len(findings),
                "critical": len(critical_findings),
                "high": len(high_findings),
            },
            "top_risks": self._identify_top_risks(findings),
            "recommendations": self._generate_top_recommendations(findings, threats),
            "threat_landscape": {
                "total_threats": len(threats),
                "total_detections": len(detections),
            },
        }
        
        logger.info("Generated executive summary")
        return summary
    
    def _create_overview(
        self,
        findings: List[Finding],
        threats: List[Threat],
        detections: List[Detection]
    ) -> str:
        """Create an overview of the security assessment."""
        return (
            f"Security assessment identified {len(findings)} findings, "
            f"{len(threats)} threats, and {len(detections)} detections. "
            f"Immediate attention required for {len([f for f in findings if f.severity.value in ['critical', 'high']])} "
            "high-priority issues."
        )
    
    def _identify_top_risks(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Identify the top risks from findings."""
        sorted_findings = sorted(
            findings,
            key=lambda f: (f.cvss_score or 0, f.severity.value),
            reverse=True
        )
        
        top_risks = []
        for finding in sorted_findings[:5]:
            top_risks.append({
                "title": finding.title,
                "severity": finding.severity.value,
                "cvss_score": finding.cvss_score,
            })
        
        return top_risks
    
    def _generate_top_recommendations(
        self,
        findings: List[Finding],
        threats: List[Threat]
    ) -> List[str]:
        """Generate top recommendations based on findings and threats."""
        recommendations = []
        
        critical_count = len([f for f in findings if f.severity.value == "critical"])
        if critical_count > 0:
            recommendations.append(
                f"Immediately address {critical_count} critical findings to reduce risk"
            )
        
        patch_needed = len([f for f in findings if f.cve_ids])
        if patch_needed > 0:
            recommendations.append(
                f"Apply security patches for {patch_needed} vulnerabilities"
            )
        
        if threats:
            recommendations.append(
                "Implement threat mitigation controls based on identified threats"
            )
        
        recommendations.append("Conduct regular security assessments to maintain posture")
        
        return recommendations[:5]
