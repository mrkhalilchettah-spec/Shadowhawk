"""
ShadowHawk Platform - Threat Modeling Engine

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import List, Dict, Any, Optional
from uuid import UUID
import logging

from ...domain.models.asset import Asset, AssetType, Criticality
from ...domain.models.threat import Threat, StrideCategory, ThreatCategory

logger = logging.getLogger(__name__)


class ThreatModelingEngine:
    """
    Threat Modeling Engine with STRIDE classification.
    
    Performs asset-based threat modeling to identify potential security threats
    using the STRIDE methodology.
    """
    
    def __init__(self):
        """Initialize the threat modeling engine."""
        self.stride_patterns = self._initialize_stride_patterns()
    
    def _initialize_stride_patterns(self) -> Dict[AssetType, List[StrideCategory]]:
        """Initialize STRIDE patterns for different asset types."""
        return {
            AssetType.APPLICATION: [
                StrideCategory.SPOOFING,
                StrideCategory.TAMPERING,
                StrideCategory.REPUDIATION,
                StrideCategory.INFORMATION_DISCLOSURE,
                StrideCategory.DENIAL_OF_SERVICE,
                StrideCategory.ELEVATION_OF_PRIVILEGE,
            ],
            AssetType.DATABASE: [
                StrideCategory.TAMPERING,
                StrideCategory.INFORMATION_DISCLOSURE,
                StrideCategory.DENIAL_OF_SERVICE,
                StrideCategory.ELEVATION_OF_PRIVILEGE,
            ],
            AssetType.API: [
                StrideCategory.SPOOFING,
                StrideCategory.TAMPERING,
                StrideCategory.REPUDIATION,
                StrideCategory.INFORMATION_DISCLOSURE,
                StrideCategory.DENIAL_OF_SERVICE,
                StrideCategory.ELEVATION_OF_PRIVILEGE,
            ],
            AssetType.NETWORK: [
                StrideCategory.SPOOFING,
                StrideCategory.TAMPERING,
                StrideCategory.INFORMATION_DISCLOSURE,
                StrideCategory.DENIAL_OF_SERVICE,
            ],
            AssetType.SERVER: [
                StrideCategory.SPOOFING,
                StrideCategory.TAMPERING,
                StrideCategory.DENIAL_OF_SERVICE,
                StrideCategory.ELEVATION_OF_PRIVILEGE,
            ],
        }
    
    def analyze_asset(self, asset: Asset) -> List[Threat]:
        """
        Analyze an asset and generate potential threats.
        
        Args:
            asset: The asset to analyze
            
        Returns:
            List of identified threats
        """
        logger.info(f"Analyzing asset: {asset.name} (type: {asset.asset_type.value})")
        
        threats = []
        stride_categories = self.stride_patterns.get(
            asset.asset_type,
            [StrideCategory.TAMPERING, StrideCategory.INFORMATION_DISCLOSURE]
        )
        
        for stride_category in stride_categories:
            threat = self._generate_threat_for_stride(asset, stride_category)
            if threat:
                threats.append(threat)
        
        logger.info(f"Generated {len(threats)} threats for asset {asset.name}")
        return threats
    
    def _generate_threat_for_stride(
        self,
        asset: Asset,
        stride_category: StrideCategory
    ) -> Optional[Threat]:
        """
        Generate a threat for a specific STRIDE category.
        
        Args:
            asset: The asset being analyzed
            stride_category: The STRIDE category to generate threat for
            
        Returns:
            Generated threat or None
        """
        threat_templates = {
            StrideCategory.SPOOFING: {
                "title": f"Identity Spoofing Attack on {asset.name}",
                "description": f"Attacker could impersonate legitimate users or systems to gain unauthorized access to {asset.name}.",
                "impact": "high" if asset.criticality in [Criticality.CRITICAL, Criticality.HIGH] else "medium",
                "likelihood": "medium",
                "mitigations": [
                    "Implement strong authentication mechanisms",
                    "Use multi-factor authentication",
                    "Monitor authentication attempts",
                ]
            },
            StrideCategory.TAMPERING: {
                "title": f"Data Tampering Threat on {asset.name}",
                "description": f"Unauthorized modification of data or code in {asset.name} could lead to integrity violations.",
                "impact": "high" if asset.criticality == Criticality.CRITICAL else "medium",
                "likelihood": "medium",
                "mitigations": [
                    "Implement integrity checks and validation",
                    "Use digital signatures",
                    "Enable audit logging",
                ]
            },
            StrideCategory.REPUDIATION: {
                "title": f"Repudiation Attack on {asset.name}",
                "description": f"Users could deny performing actions on {asset.name} due to insufficient logging.",
                "impact": "medium",
                "likelihood": "low",
                "mitigations": [
                    "Implement comprehensive audit logging",
                    "Use non-repudiation mechanisms",
                    "Store logs securely",
                ]
            },
            StrideCategory.INFORMATION_DISCLOSURE: {
                "title": f"Information Disclosure on {asset.name}",
                "description": f"Sensitive information in {asset.name} could be exposed to unauthorized parties.",
                "impact": "high" if asset.criticality in [Criticality.CRITICAL, Criticality.HIGH] else "medium",
                "likelihood": "medium",
                "mitigations": [
                    "Implement encryption at rest and in transit",
                    "Apply principle of least privilege",
                    "Sanitize error messages",
                ]
            },
            StrideCategory.DENIAL_OF_SERVICE: {
                "title": f"Denial of Service Attack on {asset.name}",
                "description": f"Attacker could overwhelm {asset.name} making it unavailable to legitimate users.",
                "impact": "high" if asset.criticality == Criticality.CRITICAL else "medium",
                "likelihood": "medium",
                "mitigations": [
                    "Implement rate limiting",
                    "Use load balancing",
                    "Deploy DDoS protection",
                ]
            },
            StrideCategory.ELEVATION_OF_PRIVILEGE: {
                "title": f"Privilege Escalation on {asset.name}",
                "description": f"Attacker could gain elevated privileges on {asset.name} beyond their authorization.",
                "impact": "critical" if asset.criticality == Criticality.CRITICAL else "high",
                "likelihood": "medium",
                "mitigations": [
                    "Implement strict access controls",
                    "Regular security audits",
                    "Apply principle of least privilege",
                ]
            },
        }
        
        template = threat_templates.get(stride_category)
        if not template:
            return None
        
        threat = Threat(
            title=template["title"],
            description=template["description"],
            asset_id=asset.id,
            stride_categories=[stride_category],
            impact=template["impact"],
            likelihood=template["likelihood"],
            mitigations=template["mitigations"],
        )
        
        return threat
    
    def analyze_multiple_assets(self, assets: List[Asset]) -> Dict[UUID, List[Threat]]:
        """
        Analyze multiple assets and generate threat models.
        
        Args:
            assets: List of assets to analyze
            
        Returns:
            Dictionary mapping asset IDs to their threats
        """
        results = {}
        
        for asset in assets:
            threats = self.analyze_asset(asset)
            results[asset.id] = threats
        
        return results
    
    def generate_threat_report(self, asset: Asset, threats: List[Threat]) -> Dict[str, Any]:
        """
        Generate a threat modeling report for an asset.
        
        Args:
            asset: The analyzed asset
            threats: List of identified threats
            
        Returns:
            Threat modeling report
        """
        stride_summary = {}
        for threat in threats:
            for category in threat.stride_categories:
                stride_summary[category.value] = stride_summary.get(category.value, 0) + 1
        
        return {
            "asset": asset.to_dict(),
            "threat_count": len(threats),
            "stride_summary": stride_summary,
            "threats": [threat.to_dict() for threat in threats],
            "recommendations": self._generate_recommendations(asset, threats),
        }
    
    def _generate_recommendations(
        self,
        asset: Asset,
        threats: List[Threat]
    ) -> List[str]:
        """
        Generate security recommendations based on identified threats.
        
        Args:
            asset: The analyzed asset
            threats: List of identified threats
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if asset.criticality in [Criticality.CRITICAL, Criticality.HIGH]:
            recommendations.append("Prioritize security controls for this critical asset")
            recommendations.append("Conduct regular security assessments")
        
        stride_categories = set()
        for threat in threats:
            stride_categories.update(threat.stride_categories)
        
        if StrideCategory.SPOOFING in stride_categories:
            recommendations.append("Implement strong authentication and identity verification")
        
        if StrideCategory.INFORMATION_DISCLOSURE in stride_categories:
            recommendations.append("Ensure encryption of sensitive data at rest and in transit")
        
        if StrideCategory.ELEVATION_OF_PRIVILEGE in stride_categories:
            recommendations.append("Review and restrict privilege assignments")
        
        return recommendations
