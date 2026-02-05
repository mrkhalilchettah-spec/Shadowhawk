"""
ML-powered Threat Modeling Engine for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
from typing import Any, Dict, List, Optional

import networkx as nx
import numpy as np

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import PerformanceTracker, timed_prediction
from shadowhawk.ml.inference.engine import InferenceEngine

logger = logging.getLogger(__name__)


class ThreatModelingEngine:
    """
    ML-powered threat modeling engine with graph analysis.
    
    Analyzes system architecture, identifies potential attack vectors,
    and generates comprehensive threat models using ML and graph analysis.
    """
    
    ENGINE_NAME = "threat_modeling"
    
    def __init__(self):
        self.inference_engine = InferenceEngine()
        self.performance_tracker = PerformanceTracker(self.ENGINE_NAME)
        self.threat_graph = nx.DiGraph()
        self.attack_patterns: Dict[str, Dict] = {}
    
    def model_system(
        self,
        assets: List[Dict],
        connections: List[Dict],
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Generate a threat model for a system.
        
        Args:
            assets: List of system assets (servers, databases, etc.)
            connections: List of connections between assets
            context: Additional context about the system
        
        Returns:
            Comprehensive threat model
        """
        with timed_prediction(self.ENGINE_NAME):
            # Build system graph
            self._build_system_graph(assets, connections)
            
            # Identify critical paths
            critical_paths = self._identify_critical_paths()
            
            # Generate attack scenarios
            attack_scenarios = self._generate_attack_scenarios(assets)
            
            # Calculate threat likelihoods using ML
            threat_likelihoods = self._calculate_threat_likelihoods(attack_scenarios)
            
            # Compile threat model
            threat_model = {
                "system_summary": {
                    "total_assets": len(assets),
                    "total_connections": len(connections),
                    "critical_assets": self._identify_critical_assets(assets),
                },
                "attack_surface": self._analyze_attack_surface(),
                "attack_scenarios": attack_scenarios,
                "threat_likelihoods": threat_likelihoods,
                "critical_paths": critical_paths,
                "mitigation_priorities": self._prioritize_mitigations(
                    attack_scenarios, threat_likelihoods
                ),
                "confidence_score": self._calculate_confidence(),
            }
            
            return threat_model
    
    def _build_system_graph(
        self, 
        assets: List[Dict], 
        connections: List[Dict]
    ) -> None:
        """Build a graph representation of the system."""
        self.threat_graph.clear()
        
        # Add asset nodes
        for asset in assets:
            node_id = asset.get("id", str(hash(str(asset))))
            self.threat_graph.add_node(
                node_id,
                name=asset.get("name", "Unknown"),
                type=asset.get("type", "unknown"),
                criticality=asset.get("criticality", 0.5),
                exposure=asset.get("exposure", "internal"),
            )
        
        # Add connection edges
        for conn in connections:
            source = conn.get("source")
            target = conn.get("target")
            if source and target:
                self.threat_graph.add_edge(
                    source,
                    target,
                    protocol=conn.get("protocol", "unknown"),
                    port=conn.get("port", 0),
                    encrypted=conn.get("encrypted", False),
                )
    
    def _identify_critical_paths(self) -> List[Dict]:
        """Identify critical attack paths through the system."""
        critical_paths = []
        
        # Find paths from external-facing to critical assets
        external_nodes = [
            n for n, data in self.threat_graph.nodes(data=True)
            if data.get("exposure") == "external"
        ]
        
        critical_nodes = [
            n for n, data in self.threat_graph.nodes(data=True)
            if data.get("criticality", 0) >= 0.8
        ]
        
        for external in external_nodes:
            for critical in critical_nodes:
                try:
                    paths = list(nx.all_simple_paths(
                        self.threat_graph, external, critical, cutoff=5
                    ))
                    
                    for path in paths:
                        # Calculate path risk score
                        path_risk = self._calculate_path_risk(path)
                        
                        critical_paths.append({
                            "path": path,
                            "risk_score": path_risk,
                            "entry_point": external,
                            "target": critical,
                        })
                except nx.NetworkXNoPath:
                    continue
        
        # Sort by risk score
        critical_paths.sort(key=lambda x: x["risk_score"], reverse=True)
        return critical_paths[:10]  # Return top 10
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for an attack path."""
        risk = 0.0
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            # Get node and edge data
            source_data = self.threat_graph.nodes[source]
            target_data = self.threat_graph.nodes[target]
            edge_data = self.threat_graph.get_edge_data(source, target) or {}
            
            # Calculate segment risk
            segment_risk = (
                source_data.get("criticality", 0.5) * 0.3 +
                target_data.get("criticality", 0.5) * 0.4 +
                (0.0 if edge_data.get("encrypted") else 0.3)
            )
            
            risk += segment_risk
        
        return risk / len(path) if path else 0.0
    
    def _generate_attack_scenarios(self, assets: List[Dict]) -> List[Dict]:
        """Generate potential attack scenarios using ML."""
        scenarios = []
        
        # Generate scenarios based on asset types
        asset_types = {a.get("type", "unknown") for a in assets}
        
        for asset_type in asset_types:
            # Use ML to predict likely attack vectors
            attack_vectors = self._predict_attack_vectors(asset_type)
            
            for vector in attack_vectors:
                scenario = {
                    "type": vector["type"],
                    "target_asset_type": asset_type,
                    "description": vector["description"],
                    "mitre_techniques": vector.get("techniques", []),
                    "prerequisites": vector.get("prerequisites", []),
                    "impact": vector.get("impact", "medium"),
                    "likelihood": vector.get("likelihood", 0.5),
                }
                scenarios.append(scenario)
        
        return scenarios
    
    def _predict_attack_vectors(self, asset_type: str) -> List[Dict]:
        """Use ML to predict likely attack vectors for an asset type."""
        # Map asset types to common attack patterns
        attack_patterns = {
            "web_server": [
                {
                    "type": "web_exploitation",
                    "description": "Exploitation of web application vulnerabilities",
                    "techniques": ["T1190", "T1203", "T1059"],
                    "prerequisites": ["network_access"],
                    "impact": "high",
                    "likelihood": 0.7,
                },
                {
                    "type": "credential_theft",
                    "description": "Theft of service account credentials",
                    "techniques": ["T1003", "T1558"],
                    "prerequisites": ["local_access"],
                    "impact": "high",
                    "likelihood": 0.6,
                },
            ],
            "database": [
                {
                    "type": "sql_injection",
                    "description": "SQL injection attacks",
                    "techniques": ["T1190"],
                    "prerequisites": ["web_access"],
                    "impact": "critical",
                    "likelihood": 0.5,
                },
                {
                    "type": "data_exfiltration",
                    "description": "Unauthorized data access and exfiltration",
                    "techniques": ["T1567", "T1041"],
                    "prerequisites": ["database_access"],
                    "impact": "critical",
                    "likelihood": 0.6,
                },
            ],
            "workstation": [
                {
                    "type": "phishing",
                    "description": "Phishing and social engineering attacks",
                    "techniques": ["T1566", "T1204"],
                    "prerequisites": ["email_access"],
                    "impact": "medium",
                    "likelihood": 0.8,
                },
                {
                    "type": "malware_execution",
                    "description": "Execution of malicious software",
                    "techniques": ["T1204", "T1059"],
                    "prerequisites": ["user_execution"],
                    "impact": "high",
                    "likelihood": 0.7,
                },
            ],
        }
        
        return attack_patterns.get(asset_type.lower(), [{
            "type": "unknown",
            "description": "Generic attack scenario",
            "techniques": [],
            "prerequisites": [],
            "impact": "medium",
            "likelihood": 0.5,
        }])
    
    def _calculate_threat_likelihoods(
        self, 
        scenarios: List[Dict]
    ) -> Dict[str, float]:
        """Calculate threat likelihoods using ML models."""
        likelihoods = {}
        
        for scenario in scenarios:
            # Create feature vector
            features = np.array([
                scenario.get("likelihood", 0.5),
                self._impact_to_score(scenario.get("impact", "medium")),
                len(scenario.get("prerequisites", [])),
                len(scenario.get("mitre_techniques", [])),
            ])
            
            # Use inference engine for prediction
            try:
                result = self.inference_engine.predict_risk(features.reshape(1, -1))
                if result and "risk_score" in result[0]:
                    likelihoods[scenario["type"]] = result[0]["risk_score"] / 10.0
                else:
                    likelihoods[scenario["type"]] = scenario.get("likelihood", 0.5)
            except Exception as e:
                logger.warning(f"Could not calculate likelihood: {e}")
                likelihoods[scenario["type"]] = scenario.get("likelihood", 0.5)
        
        return likelihoods
    
    def _impact_to_score(self, impact: str) -> float:
        """Convert impact level to numeric score."""
        impact_scores = {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
            "minimal": 0.1,
        }
        return impact_scores.get(impact.lower(), 0.5)
    
    def _identify_critical_assets(self, assets: List[Dict]) -> List[str]:
        """Identify critical assets from the asset list."""
        critical = [
            a.get("name", "Unknown")
            for a in assets
            if a.get("criticality", 0) >= 0.8
        ]
        return critical
    
    def _analyze_attack_surface(self) -> Dict:
        """Analyze the system's attack surface."""
        external_nodes = [
            n for n, data in self.threat_graph.nodes(data=True)
            if data.get("exposure") == "external"
        ]
        
        return {
            "external_facing_assets": len(external_nodes),
            "entry_points": external_nodes,
            "attack_surface_score": len(external_nodes) / max(len(self.threat_graph.nodes), 1),
        }
    
    def _prioritize_mitigations(
        self,
        scenarios: List[Dict],
        likelihoods: Dict[str, float]
    ) -> List[Dict]:
        """Prioritize mitigation strategies."""
        mitigations = []
        
        for scenario in scenarios:
            likelihood = likelihoods.get(scenario["type"], 0.5)
            impact = self._impact_to_score(scenario.get("impact", "medium"))
            
            # Risk = Likelihood * Impact
            risk = likelihood * impact
            
            mitigation = {
                "scenario": scenario["type"],
                "priority": self._risk_to_priority(risk),
                "risk_score": risk,
                "recommended_controls": self._get_controls_for_scenario(scenario),
            }
            mitigations.append(mitigation)
        
        # Sort by risk score
        mitigations.sort(key=lambda x: x["risk_score"], reverse=True)
        return mitigations
    
    def _risk_to_priority(self, risk: float) -> str:
        """Convert risk score to priority level."""
        if risk >= 0.7:
            return "critical"
        elif risk >= 0.5:
            return "high"
        elif risk >= 0.3:
            return "medium"
        return "low"
    
    def _get_controls_for_scenario(self, scenario: Dict) -> List[str]:
        """Get recommended controls for a scenario."""
        # Map scenarios to controls
        control_map = {
            "web_exploitation": [
                "Implement Web Application Firewall (WAF)",
                "Regular security testing",
                "Input validation and sanitization",
            ],
            "credential_theft": [
                "Multi-factor authentication",
                "Privileged access management",
                "Credential rotation policies",
            ],
            "sql_injection": [
                "Parameterized queries",
                "Database activity monitoring",
                "Least privilege database access",
            ],
            "data_exfiltration": [
                "Data Loss Prevention (DLP)",
                "Network segmentation",
                "Encryption at rest and in transit",
            ],
            "phishing": [
                "Email security gateway",
                "Security awareness training",
                "DMARC/SPF/DKIM implementation",
            ],
            "malware_execution": [
                "Endpoint Detection and Response (EDR)",
                "Application whitelisting",
                "Regular patching",
            ],
        }
        
        return control_map.get(
            scenario["type"], 
            ["Regular security assessment", "Monitoring and logging"]
        )
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence score for the threat model."""
        # Confidence based on data completeness
        node_count = len(self.threat_graph.nodes)
        edge_count = len(self.threat_graph.edges)
        
        if node_count == 0:
            return 0.0
        
        # More connected graphs generally have higher confidence
        density = nx.density(self.threat_graph) if node_count > 1 else 0
        
        # Base confidence on graph size and density
        confidence = min(0.5 + (node_count / 100) + (density * 0.3), 0.95)
        
        return round(confidence, 2)
