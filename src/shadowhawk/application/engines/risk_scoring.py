"""
 cto-task-goaldesign-and-implement-the-initial-architecture-and-core-m
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

ML-powered Risk Scoring Engine for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
from typing import Any, Dict, List, Optional

import numpy as np

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import PerformanceTracker, timed_prediction
from shadowhawk.ml.inference.engine import InferenceEngine
 main

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
 cto-task-goaldesign-and-implement-the-initial-architecture-and-core-m
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

    ML-powered dynamic risk scoring engine.
    
    Calculates comprehensive risk scores based on multiple factors
    including vulnerability data, threat intelligence, and asset context.
    """
    
    ENGINE_NAME = "risk_scoring"
    
    def __init__(self):
        self.inference_engine = InferenceEngine()
        self.performance_tracker = PerformanceTracker(self.ENGINE_NAME)
        
        # Risk thresholds
        self.critical_threshold = 9.0
        self.high_threshold = 7.0
        self.medium_threshold = 4.0
        
        # Risk history
        self.risk_history: List[Dict] = []
    
    def calculate_risk(
        self,
        vulnerability: Dict[str, Any],
        threat_intel: Optional[Dict] = None,
        asset_context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for a vulnerability.
        
        Args:
            vulnerability: Vulnerability data
            threat_intel: Threat intelligence data
            asset_context: Asset context information
        
        Returns:
            Risk assessment with score and components
        """
        with timed_prediction(self.ENGINE_NAME):
            # Extract risk factors
            risk_factors = self._extract_risk_factors(
                vulnerability, threat_intel, asset_context
            )
            
            # Calculate component scores
            vulnerability_score = self._calculate_vulnerability_score(vulnerability)
            threat_score = self._calculate_threat_score(threat_intel)
            asset_score = self._calculate_asset_score(asset_context)
            exploitability_score = self._calculate_exploitability(
                vulnerability, threat_intel
            )
            
            # Use ML model for final risk prediction
            features = np.array([
                vulnerability_score / 10.0,
                threat_score,
                asset_score,
                exploitability_score,
                risk_factors.get("exposure_level", 0.5),
                risk_factors.get("mitigation_effectiveness", 0.5),
            ])
            
            try:
                ml_result = self.inference_engine.predict_risk(
                    features.reshape(1, -1),
                    context=[risk_factors]
                )
                
                if ml_result and "risk_score" in ml_result[0]:
                    overall_risk = ml_result[0]["risk_score"]
                    confidence = ml_result[0].get("confidence", 0.8)
                else:
                    overall_risk = self._calculate_weighted_risk([
                        vulnerability_score,
                        threat_score * 10,
                        asset_score * 10,
                        exploitability_score * 10,
                    ])
                    confidence = 0.7
            
            except Exception as e:
                logger.warning(f"ML risk prediction failed: {e}")
                overall_risk = self._calculate_weighted_risk([
                    vulnerability_score,
                    threat_score * 10,
                    asset_score * 10,
                    exploitability_score * 10,
                ])
                confidence = 0.6
            
            # Build risk assessment
            assessment = {
                "vulnerability_id": vulnerability.get("id", "unknown"),
                "overall_risk_score": round(overall_risk, 2),
                "risk_level": self._score_to_level(overall_risk),
                "confidence": round(confidence, 3),
                "component_scores": {
                    "vulnerability": round(vulnerability_score, 2),
                    "threat": round(threat_score * 10, 2),
                    "asset": round(asset_score * 10, 2),
                    "exploitability": round(exploitability_score * 10, 2),
                },
                "risk_factors": risk_factors,
                "prioritization_score": self._calculate_prioritization_score(
                    overall_risk, confidence
                ),
                "recommended_actions": self._generate_recommendations(
                    overall_risk, risk_factors
                ),
            }
            
            self.risk_history.append(assessment)
            
            return assessment
    
    def calculate_portfolio_risk(
        self, 
        vulnerabilities: List[Dict],
        asset_inventory: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Calculate portfolio-level risk across all vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
            asset_inventory: Optional asset inventory
        
        Returns:
            Portfolio risk assessment
        """
        if not vulnerabilities:
            return {
                "total_vulnerabilities": 0,
                "average_risk": 0.0,
                "risk_distribution": {},
            }
        
        individual_scores = []
        for vuln in vulnerabilities:
            assessment = self.calculate_risk(vuln)
            individual_scores.append(assessment)
        
        # Calculate statistics
        scores = [a["overall_risk_score"] for a in individual_scores]
        
        # Risk distribution
        distribution = {
            "critical": sum(1 for s in scores if s >= self.critical_threshold),
            "high": sum(1 for s in scores if self.high_threshold <= s < self.critical_threshold),
            "medium": sum(1 for s in scores if self.medium_threshold <= s < self.high_threshold),
            "low": sum(1 for s in scores if s < self.medium_threshold),
        }
        
        # Top risks
        top_risks = sorted(individual_scores, key=lambda x: x["overall_risk_score"], reverse=True)[:10]
        
        portfolio_risk = {
            "total_vulnerabilities": len(vulnerabilities),
            "average_risk": round(np.mean(scores), 2),
            "max_risk": round(max(scores), 2),
            "risk_distribution": distribution,
            "risk_concentration": self._calculate_risk_concentration(scores),
            "top_risks": [
                {
                    "vulnerability_id": r["vulnerability_id"],
                    "risk_score": r["overall_risk_score"],
                    "risk_level": r["risk_level"],
                }
                for r in top_risks
            ],
            "trend": self._calculate_risk_trend(),
        }
        
        return portfolio_risk
    
    def _extract_risk_factors(
        self,
        vulnerability: Dict,
        threat_intel: Optional[Dict],
        asset_context: Optional[Dict]
    ) -> Dict[str, float]:
        """Extract risk factor values."""
        factors = {
            # Vulnerability factors
            "cvss_score": vulnerability.get("cvss_score", 5.0) / 10.0,
            "epss_score": vulnerability.get("epss_score", 0.5),
            "exploit_available": 1.0 if vulnerability.get("exploit_available") else 0.0,
            "patch_available": 1.0 if vulnerability.get("patch_available") else 0.0,
            
            # Asset factors
            "asset_criticality": asset_context.get("criticality", 0.5) if asset_context else 0.5,
            "exposure_level": asset_context.get("exposure_level", 0.3) if asset_context else 0.3,
            "data_sensitivity": asset_context.get("data_sensitivity", 0.5) if asset_context else 0.5,
            
            # Threat factors
            "threat_actor_activity": threat_intel.get("actor_activity", 0.5) if threat_intel else 0.5,
            "exploit_maturity": threat_intel.get("exploit_maturity", 0.5) if threat_intel else 0.5,
            
            # Mitigation factors
            "mitigation_effectiveness": vulnerability.get("mitigation_effectiveness", 0.5),
            "detection_capability": asset_context.get("detection_capability", 0.5) if asset_context else 0.5,
        }
        
        return factors
    
    def _calculate_vulnerability_score(self, vulnerability: Dict) -> float:
        """Calculate vulnerability-specific risk score."""
        cvss = vulnerability.get("cvss_score", 5.0)
        epss = vulnerability.get("epss_score", 0.0)
        
        # Weight CVSS and EPSS
        score = (cvss * 0.6) + (epss * 10 * 0.4)
        
        # Adjust based on exploit availability
        if vulnerability.get("exploit_available"):
            score *= 1.2
        
        # Adjust based on patch availability
        if not vulnerability.get("patch_available"):
            score *= 1.1
        
        return min(score, 10.0)
    
    def _calculate_threat_score(self, threat_intel: Optional[Dict]) -> float:
        """Calculate threat intelligence risk score."""
        if not threat_intel:
            return 0.5
        
        # Combine threat factors
        actor_activity = threat_intel.get("actor_activity", 0.5)
        exploit_maturity = threat_intel.get("exploit_maturity", 0.5)
        threat_volume = threat_intel.get("threat_volume", 0.5)
        
        return (actor_activity * 0.4 + exploit_maturity * 0.4 + threat_volume * 0.2)
    
    def _calculate_asset_score(self, asset_context: Optional[Dict]) -> float:
        """Calculate asset context risk score."""
        if not asset_context:
            return 0.5
        
        criticality = asset_context.get("criticality", 0.5)
        exposure = asset_context.get("exposure_level", 0.3)
        sensitivity = asset_context.get("data_sensitivity", 0.5)
        
        return (criticality * 0.5 + exposure * 0.3 + sensitivity * 0.2)
    
    def _calculate_exploitability(
        self,
        vulnerability: Dict,
        threat_intel: Optional[Dict]
    ) -> float:
        """Calculate exploitability score."""
        # Base exploitability
        exploitability = 0.5
        
        # EPSS contributes significantly
        epss = vulnerability.get("epss_score", 0.5)
        exploitability = exploitability * 0.5 + epss * 0.5
        
        # Exploit availability
        if vulnerability.get("exploit_available"):
            exploitability += 0.2
        
        # Exploit maturity from threat intel
        if threat_intel and threat_intel.get("exploit_maturity"):
            exploitability = exploitability * 0.6 + threat_intel["exploit_maturity"] * 0.4
        
        # Network accessibility
        if vulnerability.get("network_accessible"):
            exploitability += 0.1
        
        return min(exploitability, 1.0)
    
    def _calculate_weighted_risk(self, scores: List[float]) -> float:
        """Calculate weighted average risk score."""
        weights = [0.35, 0.25, 0.25, 0.15]  # Vuln, Threat, Asset, Exploitability
        
        if len(scores) != len(weights):
            return np.mean(scores)
        
        weighted = sum(s * w for s, w in zip(scores, weights))
        return min(weighted, 10.0)
    
    def _score_to_level(self, score: float) -> str:
        """Convert risk score to level."""
        if score >= self.critical_threshold:
            return "critical"
        elif score >= self.high_threshold:
            return "high"
        elif score >= self.medium_threshold:
            return "medium"
        elif score >= 1.0:
            return "low"
        return "minimal"
    
    def _calculate_prioritization_score(
        self, 
        risk_score: float, 
        confidence: float
    ) -> float:
        """Calculate prioritization score for remediation."""
        # Higher risk and higher confidence = higher priority
        return round(risk_score * confidence, 2)
    
    def _generate_recommendations(
        self, 
        risk_score: float, 
        risk_factors: Dict
    ) -> List[str]:
        """Generate remediation recommendations based on risk."""
        recommendations = []
        
        if risk_score >= self.critical_threshold:
            recommendations.append("Immediate remediation required - critical risk")
            recommendations.append("Consider taking affected systems offline")
        
        if risk_score >= self.high_threshold:
            recommendations.append("High priority remediation within 24-48 hours")
        
        if risk_factors.get("exploit_available", 0) > 0.5:
            recommendations.append("Active exploits available - expedite patching")
        
        if risk_factors.get("exposure_level", 0) > 0.7:
            recommendations.append("Reduce exposure through network segmentation")
        
        if risk_factors.get("patch_available", 1) == 0:
            recommendations.append("No patch available - implement compensating controls")
        
        if not recommendations:
            recommendations.append("Standard remediation timeline applies")
            recommendations.append("Continue monitoring for changes")
        
        return recommendations
    
    def _calculate_risk_concentration(self, scores: List[float]) -> Dict:
        """Calculate risk concentration metrics."""
        if not scores:
            return {}
        
        critical_count = sum(1 for s in scores if s >= self.critical_threshold)
        high_count = sum(1 for s in scores if s >= self.high_threshold)
        
        return {
            "critical_percentage": round(critical_count / len(scores) * 100, 2),
            "high_or_above_percentage": round(high_count / len(scores) * 100, 2),
            "concentration_risk": "high" if critical_count > len(scores) * 0.1 else "normal",
        }
    
    def _calculate_risk_trend(self) -> str:
        """Calculate risk trend based on history."""
        if len(self.risk_history) < 10:
            return "insufficient_data"
        
        recent = [r["overall_risk_score"] for r in self.risk_history[-10:]]
        older = [r["overall_risk_score"] for r in self.risk_history[-20:-10]]
        
        recent_avg = np.mean(recent)
        older_avg = np.mean(older)
        
        diff = recent_avg - older_avg
        
        if diff > 0.5:
            return "increasing"
        elif diff < -0.5:
            return "decreasing"
        return "stable"
    
    def get_risk_statistics(self) -> Dict:
        """Get risk scoring statistics."""
        if not self.risk_history:
            return {"total_assessments": 0}
        
        scores = [r["overall_risk_score"] for r in self.risk_history]
        
        return {
            "total_assessments": len(self.risk_history),
            "average_risk": round(np.mean(scores), 2),
            "max_risk": round(max(scores), 2),
            "min_risk": round(min(scores), 2),
            "risk_std": round(np.std(scores), 2),
            "risk_distribution": {
                "critical": sum(1 for s in scores if s >= self.critical_threshold),
                "high": sum(1 for s in scores if self.high_threshold <= s < self.critical_threshold),
                "medium": sum(1 for s in scores if self.medium_threshold <= s < self.high_threshold),
                "low": sum(1 for s in scores if s < self.medium_threshold),
            },
 main
        }
