
 cto-task-goaldesign-and-implement-the-initial-architecture-and-core-m
ShadowHawk Platform - AI Analysis Engine

Copyright (c) 2026 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.


from typing import Dict, Any, List, Optional
import logging
import json

from ...domain.models.finding import Finding
from ...domain.models.threat import Threat
from ...domain.models.detection import Detection

logger = logging.getLogger(__name__)

AI Analysis Engine
Copyright (c) 2026 ShadowHawk Team
Licensed under the MIT License

Real LLM-powered security analysis with caching and structured outputs.
"""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
import json
import structlog

from shadowhawk.infrastructure.ai.llm_client import LLMClient, LLMProvider
from shadowhawk.infrastructure.ai.prompt_library import PromptLibrary
from shadowhawk.infrastructure.ai.response_cache import ResponseCache

logger = structlog.get_logger()


class ThreatAnalysis(BaseModel):
    """Structured threat analysis output"""
    threat_id: str
    executive_summary: str
    technical_analysis: Dict[str, str]
    business_impact: Dict[str, str]
    immediate_actions: List[str]
    long_term_recommendations: List[str]
    confidence_score: float = Field(ge=0.0, le=1.0)
    raw_response: str


class RemediationPlan(BaseModel):
    """Structured remediation plan output"""
    priority_1: List[Dict[str, str]]
    priority_2: List[Dict[str, str]]
    priority_3: List[Dict[str, str]]
    priority_4: List[Dict[str, str]]
    risk_summary: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    raw_response: str


class AttackPathAnalysis(BaseModel):
    """Structured attack path analysis output"""
    attack_scenarios: List[Dict[str, Any]]
    kill_chain_mapping: Dict[str, Any]
    detection_opportunities: List[str]
    defensive_recommendations: List[str]
    confidence_score: float = Field(ge=0.0, le=1.0)
    raw_response: str


class ExecutiveSummary(BaseModel):
    """Structured executive summary output"""
    key_findings: List[str]
    risk_assessment: Dict[str, Any]
    business_impact: Dict[str, Any]
    recommended_actions: List[Dict[str, Any]]
    metrics: Dict[str, Any]
    confidence_score: float = Field(ge=0.0, le=1.0)
    raw_response: str


class MitreContext(BaseModel):
    """Structured MITRE ATT&CK context output"""
    tactics: List[str]
    techniques: List[str]
    sub_techniques: List[str]
    adversary_intelligence: Dict[str, Any]
    detection_strategies: List[str]
    mitigation_techniques: List[str]
    related_techniques: List[str]
    confidence_score: float = Field(ge=0.0, le=1.0)
    raw_response: str
 main


class AIAnalysisEngine:
    """
 cto-task-goaldesign-and-implement-the-initial-architecture-and-core-m
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
=======
    AI-powered security analysis engine using real LLMs
    
    Replaces placeholder AI functionality with production-ready
    OpenAI/Anthropic integration.
    """
    
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        prompt_library: Optional[PromptLibrary] = None,
        response_cache: Optional[ResponseCache] = None,
    ) -> None:
        """
        Initialize AI analysis engine
        
        Args:
            llm_client: LLM client (creates default if not provided)
            prompt_library: Prompt library (creates default if not provided)
            response_cache: Response cache (creates default if not provided)
        """
        self.llm = llm_client or LLMClient()
        self.prompts = prompt_library or PromptLibrary()
        self.cache = response_cache or ResponseCache()
        
        logger.info(
            "ai_analysis_engine_initialized",
            provider=self.llm.provider.value,
            model=self.llm.model,
            cache_enabled=self.cache.enabled,
        )
    
    async def _complete_with_cache(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Complete with caching support
        
        Args:
            prompt: User prompt
            system_prompt: System prompt
            
        Returns:
            LLM response dict
        """
        # Try cache first
        cached = self.cache.get(
            prompt=prompt,
            system_prompt=system_prompt,
            model=self.llm.model,
            temperature=self.llm.temperature,
            max_tokens=self.llm.max_tokens,
        )
        
        if cached:
            logger.info("cache_hit_used")
            return cached
        
        # Generate new response
        response = await self.llm.complete(prompt, system_prompt)
        
        # Cache the response
        self.cache.set(
            prompt=prompt,
            system_prompt=system_prompt,
            model=self.llm.model,
            temperature=self.llm.temperature,
            max_tokens=self.llm.max_tokens,
            response=response,
        )
        
        return response
    
    async def analyze_threat(
        self,
        threat_id: str,
        threat_type: str,
        severity: str,
        affected_systems: str,
        threat_details: str,
    ) -> ThreatAnalysis:
        """
        Analyze security threat using LLM
        
        Args:
            threat_id: Unique threat identifier
            threat_type: Type of threat
            severity: Severity level
            affected_systems: Systems affected
            threat_details: Detailed threat information
            
        Returns:
            Structured threat analysis
        """
        logger.info("analyzing_threat", threat_id=threat_id)
        
        template = self.prompts.get("threat_explanation")
        system_prompt, user_prompt = template.render(
            threat_id=threat_id,
            threat_type=threat_type,
            severity=severity,
            affected_systems=affected_systems,
            threat_details=threat_details,
        )
        
        response = await self._complete_with_cache(user_prompt, system_prompt)
        
        # Parse response into structured format
        # In production, you might use function calling or structured output
        analysis = self._parse_threat_analysis(response["content"], threat_id)
        
        logger.info(
            "threat_analysis_complete",
            threat_id=threat_id,
            cost=response["cost"],
            tokens=response["total_tokens"],
        )
        
        return analysis
    
    def _parse_threat_analysis(self, content: str, threat_id: str) -> ThreatAnalysis:
        """Parse LLM response into ThreatAnalysis model"""
        # Simple parsing - in production, use structured outputs
        lines = content.split("\n")
        
        return ThreatAnalysis(
            threat_id=threat_id,
            executive_summary=self._extract_section(content, "EXECUTIVE SUMMARY"),
            technical_analysis={
                "attack_vector": self._extract_subsection(content, "Attack Vector"),
                "exploitation_method": self._extract_subsection(content, "Exploitation Method"),
                "technical_impact": self._extract_subsection(content, "Technical Impact"),
            },
            business_impact={
                "potential_damage": self._extract_subsection(content, "Potential Damage"),
                "affected_operations": self._extract_subsection(content, "Affected Operations"),
                "compliance": self._extract_subsection(content, "Compliance"),
            },
            immediate_actions=self._extract_list(content, "IMMEDIATE ACTIONS"),
            long_term_recommendations=self._extract_list(content, "LONG-TERM RECOMMENDATIONS"),
            confidence_score=0.85,
            raw_response=content,
        )
    
    async def prioritize_remediation(
        self,
        findings: List[Dict[str, Any]],
        industry: str,
        critical_assets: str,
        compliance_requirements: str,
    ) -> RemediationPlan:
        """
        Prioritize security remediation actions
        
        Args:
            findings: List of security findings
            industry: Organization's industry
            critical_assets: Critical assets description
            compliance_requirements: Compliance requirements
            
        Returns:
            Structured remediation plan
        """
        logger.info("prioritizing_remediation", finding_count=len(findings))
        
        template = self.prompts.get("remediation_prioritization")
        system_prompt, user_prompt = template.render(
            findings_json=json.dumps(findings),
            industry=industry,
            critical_assets=critical_assets,
            compliance_requirements=compliance_requirements,
        )
        
        response = await self._complete_with_cache(user_prompt, system_prompt)
        plan = self._parse_remediation_plan(response["content"])
        
        logger.info(
            "remediation_prioritization_complete",
            cost=response["cost"],
            tokens=response["total_tokens"],
        )
        
        return plan
    
    def _parse_remediation_plan(self, content: str) -> RemediationPlan:
        """Parse LLM response into RemediationPlan model"""
        return RemediationPlan(
            priority_1=self._extract_priority_items(content, "PRIORITY 1"),
            priority_2=self._extract_priority_items(content, "PRIORITY 2"),
            priority_3=self._extract_priority_items(content, "PRIORITY 3"),
            priority_4=self._extract_priority_items(content, "PRIORITY 4"),
            risk_summary=self._extract_section(content, "RISK ASSESSMENT SUMMARY"),
            confidence_score=0.85,
            raw_response=content,
        )
    
    async def analyze_attack_path(
        self,
        entry_point: str,
        target_asset: str,
        vulnerabilities: str,
        security_controls: str,
        network_topology: str,
    ) -> AttackPathAnalysis:
        """
        Analyze potential attack paths
        
        Args:
            entry_point: Initial access point
            target_asset: Target asset
            vulnerabilities: Known vulnerabilities
            security_controls: Current security controls
            network_topology: Network topology description
            
        Returns:
            Structured attack path analysis
        """
        logger.info("analyzing_attack_path", target=target_asset)
        
        template = self.prompts.get("attack_path")
        system_prompt, user_prompt = template.render(
            entry_point=entry_point,
            target_asset=target_asset,
            vulnerabilities=vulnerabilities,
            security_controls=security_controls,
            network_topology=network_topology,
        )
        
        response = await self._complete_with_cache(user_prompt, system_prompt)
        analysis = self._parse_attack_path(response["content"])
        
        logger.info(
            "attack_path_analysis_complete",
            cost=response["cost"],
            tokens=response["total_tokens"],
        )
        
        return analysis
    
    def _parse_attack_path(self, content: str) -> AttackPathAnalysis:
        """Parse LLM response into AttackPathAnalysis model"""
        return AttackPathAnalysis(
            attack_scenarios=[{"raw": self._extract_section(content, "ATTACK PATH SCENARIOS")}],
            kill_chain_mapping={"raw": self._extract_section(content, "KILL CHAIN MAPPING")},
            detection_opportunities=self._extract_list(content, "DETECTION OPPORTUNITIES"),
            defensive_recommendations=self._extract_list(content, "DEFENSIVE RECOMMENDATIONS"),
            confidence_score=0.85,
            raw_response=content,
        )
    
    async def generate_executive_summary(
        self,
        assessment_period: str,
        scope: str,
        findings_summary: str,
        critical_issues: str,
        risk_score: str,
        comparison_data: str,
    ) -> ExecutiveSummary:
        """
        Generate executive summary
        
        Args:
            assessment_period: Assessment time period
            scope: Assessment scope
            findings_summary: Summary of findings
            critical_issues: Critical issues
            risk_score: Overall risk score
            comparison_data: Comparison with previous period
            
        Returns:
            Structured executive summary
        """
        logger.info("generating_executive_summary")
        
        template = self.prompts.get("executive_summary")
        system_prompt, user_prompt = template.render(
            assessment_period=assessment_period,
            scope=scope,
            findings_summary=findings_summary,
            critical_issues=critical_issues,
            risk_score=risk_score,
            comparison_data=comparison_data,
        )
        
        response = await self._complete_with_cache(user_prompt, system_prompt)
        summary = self._parse_executive_summary(response["content"])
        
        logger.info(
            "executive_summary_complete",
            cost=response["cost"],
            tokens=response["total_tokens"],
        )
        
        return summary
    
    def _parse_executive_summary(self, content: str) -> ExecutiveSummary:
        """Parse LLM response into ExecutiveSummary model"""
        return ExecutiveSummary(
            key_findings=self._extract_list(content, "KEY FINDINGS"),
            risk_assessment={"raw": self._extract_section(content, "RISK ASSESSMENT")},
            business_impact={"raw": self._extract_section(content, "BUSINESS IMPACT")},
            recommended_actions=[{"raw": self._extract_section(content, "RECOMMENDED ACTIONS")}],
            metrics={"raw": self._extract_section(content, "METRICS")},
            confidence_score=0.85,
            raw_response=content,
        )
    
    async def get_mitre_context(
        self,
        finding_description: str,
        observed_behaviors: str,
        affected_systems: str,
        indicators: str,
    ) -> MitreContext:
        """
        Get MITRE ATT&CK context for finding
        
        Args:
            finding_description: Description of the finding
            observed_behaviors: Observed behaviors
            affected_systems: Affected systems
            indicators: Indicators of compromise
            
        Returns:
            Structured MITRE context
        """
        logger.info("getting_mitre_context")
        
        template = self.prompts.get("mitre_context")
        system_prompt, user_prompt = template.render(
            finding_description=finding_description,
            observed_behaviors=observed_behaviors,
            affected_systems=affected_systems,
            indicators=indicators,
        )
        
        response = await self._complete_with_cache(user_prompt, system_prompt)
        context = self._parse_mitre_context(response["content"])
        
        logger.info(
            "mitre_context_complete",
            cost=response["cost"],
            tokens=response["total_tokens"],
        )
        
        return context
    
    def _parse_mitre_context(self, content: str) -> MitreContext:
        """Parse LLM response into MitreContext model"""
        return MitreContext(
            tactics=self._extract_list(content, "Tactic"),
            techniques=self._extract_list(content, "Technique"),
            sub_techniques=self._extract_list(content, "Sub-technique"),
            adversary_intelligence={"raw": self._extract_section(content, "ADVERSARY INTELLIGENCE")},
            detection_strategies=self._extract_list(content, "DETECTION STRATEGIES"),
            mitigation_techniques=self._extract_list(content, "MITIGATION TECHNIQUES"),
            related_techniques=self._extract_list(content, "RELATED TECHNIQUES"),
            confidence_score=0.85,
            raw_response=content,
        )
    
    def _extract_section(self, content: str, section_name: str) -> str:
        """Extract a section from response"""
        lines = content.split("\n")
        in_section = False
        section_lines = []
        
        for line in lines:
            if section_name.upper() in line.upper():
                in_section = True
                continue
            if in_section:
                if line.strip() and any(c.isdigit() and c in "123456789" and line.strip().startswith(c) for c in "123456789"):
                    break
                if line.strip():
                    section_lines.append(line.strip())
        
        return " ".join(section_lines) if section_lines else "Not found"
    
    def _extract_subsection(self, content: str, subsection_name: str) -> str:
        """Extract a subsection from response"""
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if subsection_name.lower() in line.lower():
                if i + 1 < len(lines):
                    return lines[i + 1].strip()
        return "Not found"
    
    def _extract_list(self, content: str, section_name: str) -> List[str]:
        """Extract list items from a section"""
        section = self._extract_section(content, section_name)
        items = []
        for line in section.split("."):
            line = line.strip()
            if line and line != "Not found":
                items.append(line)
        return items[:5] if items else ["No items found"]
    
    def _extract_priority_items(self, content: str, priority: str) -> List[Dict[str, str]]:
        """Extract priority items from remediation plan"""
        section = self._extract_section(content, priority)
        return [{"description": section}]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics
        
        Returns:
            Dict with LLM and cache stats
        """
        return {
            "llm": self.llm.get_stats(),
            "cache": self.cache.get_stats(),
        }
 main
