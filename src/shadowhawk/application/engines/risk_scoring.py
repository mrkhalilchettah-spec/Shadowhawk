"""
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

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
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
        }
