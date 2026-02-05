"""
ShadowHawk Platform - Risk Scoring Engine

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import Dict, Any, Optional, List
from uuid import UUID
import logging

from ...domain.models.risk import Risk, RiskLevel
from ...domain.models.finding import Finding, FindingSeverity
from ...domain.models.asset import Asset, Criticality

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
    Risk Scoring Engine with CVSS-based and contextual scoring.
    
    Calculates risk scores based on vulnerability data and contextual factors.
    """
    
    def __init__(self):
        """Initialize the risk scoring engine."""
        self.severity_weights = {
            FindingSeverity.CRITICAL: 1.0,
            FindingSeverity.HIGH: 0.8,
            FindingSeverity.MEDIUM: 0.5,
            FindingSeverity.LOW: 0.3,
            FindingSeverity.INFO: 0.1,
        }
        
        self.criticality_multipliers = {
            Criticality.CRITICAL: 1.5,
            Criticality.HIGH: 1.3,
            Criticality.MEDIUM: 1.0,
            Criticality.LOW: 0.7,
        }
    
    def calculate_risk(
        self,
        finding: Finding,
        asset: Optional[Asset] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Risk:
        """
        Calculate risk score for a finding.
        
        Args:
            finding: The finding to assess
            asset: Optional associated asset
            context: Optional contextual information
            
        Returns:
            Calculated risk
        """
        base_score = self._calculate_base_score(finding)
        
        impact_score = self._calculate_impact_score(finding, asset)
        
        likelihood_score = self._calculate_likelihood_score(finding, context)
        
        contextual_factors = self._analyze_context(finding, asset, context)
        
        risk_score = self._combine_scores(
            base_score,
            impact_score,
            likelihood_score,
            contextual_factors
        )
        
        risk = Risk(
            title=f"Risk: {finding.title}",
            description=finding.description,
            asset_id=asset.id if asset else finding.asset_id,
            finding_id=finding.id,
            risk_score=risk_score,
            cvss_score=finding.cvss_score,
            impact_score=impact_score,
            likelihood_score=likelihood_score,
            contextual_factors=contextual_factors,
        )
        
        risk.calculate_risk_level()
        
        logger.info(
            f"Calculated risk score {risk_score:.2f} ({risk.risk_level.value}) "
            f"for finding: {finding.title}"
        )
        
        return risk
    
    def _calculate_base_score(self, finding: Finding) -> float:
        """Calculate base score from finding severity and CVSS."""
        if finding.cvss_score is not None:
            return finding.cvss_score
        
        severity_weight = self.severity_weights.get(finding.severity, 0.5)
        return severity_weight * 10.0
    
    def _calculate_impact_score(
        self,
        finding: Finding,
        asset: Optional[Asset]
    ) -> float:
        """Calculate impact score based on finding and asset criticality."""
        base_impact = self.severity_weights.get(finding.severity, 0.5) * 10.0
        
        if asset:
            multiplier = self.criticality_multipliers.get(asset.criticality, 1.0)
            return min(base_impact * multiplier, 10.0)
        
        return base_impact
    
    def _calculate_likelihood_score(
        self,
        finding: Finding,
        context: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate likelihood score based on exploitability and context."""
        base_likelihood = 5.0
        
        if not context:
            return base_likelihood
        
        if context.get("exploit_available"):
            base_likelihood += 2.0
        
        if context.get("actively_exploited"):
            base_likelihood += 2.0
        
        if context.get("internet_facing"):
            base_likelihood += 1.0
        
        if context.get("authentication_required"):
            base_likelihood -= 1.0
        
        return min(max(base_likelihood, 0.0), 10.0)
    
    def _analyze_context(
        self,
        finding: Finding,
        asset: Optional[Asset],
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze contextual factors affecting risk."""
        factors = {}
        
        if asset:
            factors["asset_criticality"] = asset.criticality.value
            factors["asset_type"] = asset.asset_type.value
        
        if context:
            factors["exploit_available"] = context.get("exploit_available", False)
            factors["actively_exploited"] = context.get("actively_exploited", False)
            factors["internet_facing"] = context.get("internet_facing", False)
            factors["authentication_required"] = context.get("authentication_required", True)
            factors["patch_available"] = context.get("patch_available", False)
        
        if finding.cve_ids:
            factors["has_cve"] = True
            factors["cve_count"] = len(finding.cve_ids)
        
        if finding.mitre_techniques:
            factors["mitre_techniques"] = len(finding.mitre_techniques)
        
        return factors
    
    def _combine_scores(
        self,
        base_score: float,
        impact_score: float,
        likelihood_score: float,
        contextual_factors: Dict[str, Any]
    ) -> float:
        """Combine all scores into final risk score."""
        risk_score = (base_score + impact_score + likelihood_score) / 3
        
        if contextual_factors.get("exploit_available") and contextual_factors.get("actively_exploited"):
            risk_score = min(risk_score * 1.2, 10.0)
        
        if contextual_factors.get("patch_available"):
            risk_score = max(risk_score * 0.9, 0.0)
        
        return round(risk_score, 2)
    
    def calculate_cvss_score(
        self,
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality_impact: str,
        integrity_impact: str,
        availability_impact: str
    ) -> float:
        """
        Calculate CVSS v3.1 base score.
        
        Args:
            attack_vector: Network (N), Adjacent (A), Local (L), Physical (P)
            attack_complexity: Low (L), High (H)
            privileges_required: None (N), Low (L), High (H)
            user_interaction: None (N), Required (R)
            scope: Unchanged (U), Changed (C)
            confidentiality_impact: None (N), Low (L), High (H)
            integrity_impact: None (N), Low (L), High (H)
            availability_impact: None (N), Low (L), High (H)
            
        Returns:
            CVSS base score (0.0-10.0)
        """
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_scores = {"L": 0.77, "H": 0.44}
        pr_scores_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_scores_changed = {"N": 0.85, "L": 0.68, "H": 0.5}
        ui_scores = {"N": 0.85, "R": 0.62}
        impact_scores = {"N": 0.0, "L": 0.22, "H": 0.56}
        
        av = av_scores.get(attack_vector.upper(), 0.85)
        ac = ac_scores.get(attack_complexity.upper(), 0.77)
        ui = ui_scores.get(user_interaction.upper(), 0.85)
        
        scope_changed = scope.upper() == "C"
        pr_scores = pr_scores_changed if scope_changed else pr_scores_unchanged
        pr = pr_scores.get(privileges_required.upper(), 0.62)
        
        c = impact_scores.get(confidentiality_impact.upper(), 0.0)
        i = impact_scores.get(integrity_impact.upper(), 0.0)
        a = impact_scores.get(availability_impact.upper(), 0.0)
        
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        
        exploitability = 8.22 * av * ac * pr * ui
        
        if impact <= 0:
            return 0.0
        
        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)
        
        return round(score, 1)
    
    def assess_multiple_findings(
        self,
        findings: List[Finding],
        assets: Optional[Dict[UUID, Asset]] = None
    ) -> List[Risk]:
        """
        Assess risk for multiple findings.
        
        Args:
            findings: List of findings to assess
            assets: Optional dictionary mapping asset IDs to assets
            
        Returns:
            List of calculated risks
        """
        risks = []
        
        for finding in findings:
            asset = None
            if assets and finding.asset_id:
                asset = assets.get(finding.asset_id)
            
            risk = self.calculate_risk(finding, asset)
            risks.append(risk)
        
        logger.info(f"Assessed risk for {len(findings)} findings")
        return risks
    
    def generate_risk_summary(self, risks: List[Risk]) -> Dict[str, Any]:
        """
        Generate a summary of risk assessments.
        
        Args:
            risks: List of risks
            
        Returns:
            Risk summary
        """
        level_counts = {}
        total_score = 0.0
        
        for risk in risks:
            level_counts[risk.risk_level.value] = level_counts.get(risk.risk_level.value, 0) + 1
            total_score += risk.risk_score
        
        avg_score = total_score / len(risks) if risks else 0.0
        
        return {
            "total_risks": len(risks),
            "average_risk_score": round(avg_score, 2),
            "risk_level_distribution": level_counts,
            "critical_count": level_counts.get("critical", 0),
            "high_count": level_counts.get("high", 0),
            "medium_count": level_counts.get("medium", 0),
            "low_count": level_counts.get("low", 0),
        }
