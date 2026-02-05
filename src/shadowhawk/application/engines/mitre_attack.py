"""
ShadowHawk Platform - MITRE ATT&CK Mapping Engine

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import List, Dict, Any, Optional
import logging
import re

from ...domain.models.finding import Finding
from ...domain.models.detection import Detection

logger = logging.getLogger(__name__)


class MitreAttackEngine:
    """
    MITRE ATT&CK Mapping Engine for automatic technique mapping.
    
    Maps security findings and detections to MITRE ATT&CK framework.
    """
    
    def __init__(self):
        """Initialize the MITRE ATT&CK engine."""
        self.technique_database = self._initialize_technique_database()
        self.tactic_mapping = self._initialize_tactic_mapping()
    
    def _initialize_technique_database(self) -> Dict[str, Dict[str, Any]]:
        """Initialize MITRE ATT&CK technique database."""
        return {
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": ["execution"],
                "description": "Adversaries may abuse command and script interpreters",
                "keywords": ["powershell", "cmd", "bash", "script", "interpreter"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "T1059.001": {
                "name": "PowerShell",
                "tactic": ["execution"],
                "description": "Adversaries may abuse PowerShell commands",
                "keywords": ["powershell", "ps1", "powershell.exe"],
                "platforms": ["Windows"],
            },
            "T1059.003": {
                "name": "Windows Command Shell",
                "tactic": ["execution"],
                "description": "Adversaries may abuse the Windows command shell",
                "keywords": ["cmd.exe", "command.com", "batch"],
                "platforms": ["Windows"],
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
                "description": "Adversaries may obtain and abuse credentials",
                "keywords": ["login", "authentication", "credential", "password"],
                "platforms": ["Windows", "Linux", "macOS", "Cloud"],
            },
            "T1110": {
                "name": "Brute Force",
                "tactic": ["credential-access"],
                "description": "Adversaries may use brute force techniques",
                "keywords": ["brute force", "password spray", "credential stuffing"],
                "platforms": ["Windows", "Linux", "macOS", "Cloud"],
            },
            "T1566": {
                "name": "Phishing",
                "tactic": ["initial-access"],
                "description": "Adversaries may send phishing messages",
                "keywords": ["phishing", "spear phishing", "email"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": ["command-and-control"],
                "description": "Adversaries may communicate using application layer protocols",
                "keywords": ["http", "https", "dns", "protocol"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactic": ["initial-access"],
                "description": "Adversaries may exploit weaknesses in Internet-facing applications",
                "keywords": ["exploit", "vulnerability", "CVE", "public-facing"],
                "platforms": ["Windows", "Linux", "macOS", "Cloud"],
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": ["defense-evasion", "privilege-escalation"],
                "description": "Adversaries may inject code into processes",
                "keywords": ["injection", "dll injection", "process hollowing"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "T1070": {
                "name": "Indicator Removal",
                "tactic": ["defense-evasion"],
                "description": "Adversaries may delete or modify artifacts",
                "keywords": ["clear logs", "delete", "remove evidence"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "T1486": {
                "name": "Data Encrypted for Impact",
                "tactic": ["impact"],
                "description": "Adversaries may encrypt data to impact availability",
                "keywords": ["ransomware", "encryption", "encrypt"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "T1087": {
                "name": "Account Discovery",
                "tactic": ["discovery"],
                "description": "Adversaries may attempt to get account information",
                "keywords": ["enumerate users", "whoami", "net user"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "tactic": ["command-and-control"],
                "description": "Adversaries may transfer tools or files",
                "keywords": ["download", "upload", "transfer", "wget", "curl"],
                "platforms": ["Windows", "Linux", "macOS"],
            },
        }
    
    def _initialize_tactic_mapping(self) -> Dict[str, str]:
        """Initialize MITRE ATT&CK tactic mapping."""
        return {
            "initial-access": "Initial Access",
            "execution": "Execution",
            "persistence": "Persistence",
            "privilege-escalation": "Privilege Escalation",
            "defense-evasion": "Defense Evasion",
            "credential-access": "Credential Access",
            "discovery": "Discovery",
            "lateral-movement": "Lateral Movement",
            "collection": "Collection",
            "command-and-control": "Command and Control",
            "exfiltration": "Exfiltration",
            "impact": "Impact",
        }
    
    def map_finding(self, finding: Finding) -> Finding:
        """
        Map a finding to MITRE ATT&CK techniques.
        
        Args:
            finding: The finding to map
            
        Returns:
            Updated finding with MITRE techniques
        """
        text = f"{finding.title} {finding.description}".lower()
        
        mapped_techniques = self._find_matching_techniques(text)
        
        for technique_id in mapped_techniques:
            finding.add_mitre_technique(technique_id)
            
            technique = self.technique_database[technique_id]
            for tactic in technique["tactic"]:
                if tactic not in finding.mitre_tactics:
                    finding.mitre_tactics.append(tactic)
        
        logger.info(
            f"Mapped finding '{finding.title}' to {len(mapped_techniques)} MITRE techniques"
        )
        
        return finding
    
    def map_detection(self, detection: Detection) -> Detection:
        """
        Map a detection to MITRE ATT&CK techniques.
        
        Args:
            detection: The detection to map
            
        Returns:
            Updated detection with MITRE techniques
        """
        text_parts = [
            detection.title,
            detection.description,
            str(detection.normalized_log.get("message", "")),
            str(detection.normalized_log.get("command", "")),
            str(detection.normalized_log.get("process", "")),
        ]
        
        text = " ".join(text_parts).lower()
        
        mapped_techniques = self._find_matching_techniques(text)
        
        for technique_id in mapped_techniques:
            if technique_id not in detection.mitre_techniques:
                detection.mitre_techniques.append(technique_id)
        
        logger.info(
            f"Mapped detection '{detection.title}' to {len(mapped_techniques)} MITRE techniques"
        )
        
        return detection
    
    def _find_matching_techniques(self, text: str) -> List[str]:
        """
        Find MITRE techniques that match the given text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of matching technique IDs
        """
        matches = []
        
        for technique_id, technique_data in self.technique_database.items():
            for keyword in technique_data["keywords"]:
                if re.search(r'\b' + re.escape(keyword.lower()) + r'\b', text):
                    matches.append(technique_id)
                    break
        
        return matches
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a MITRE technique.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            Technique information or None
        """
        return self.technique_database.get(technique_id)
    
    def get_tactics_for_techniques(self, technique_ids: List[str]) -> List[str]:
        """
        Get all tactics associated with a list of techniques.
        
        Args:
            technique_ids: List of MITRE technique IDs
            
        Returns:
            List of unique tactics
        """
        tactics = set()
        
        for technique_id in technique_ids:
            technique = self.technique_database.get(technique_id)
            if technique:
                tactics.update(technique["tactic"])
        
        return sorted(list(tactics))
    
    def generate_attack_matrix(
        self,
        findings: List[Finding]
    ) -> Dict[str, List[str]]:
        """
        Generate an ATT&CK matrix from findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary mapping tactics to techniques
        """
        matrix = {}
        
        for finding in findings:
            for technique_id in finding.mitre_techniques:
                technique = self.technique_database.get(technique_id)
                if technique:
                    for tactic in technique["tactic"]:
                        if tactic not in matrix:
                            matrix[tactic] = []
                        if technique_id not in matrix[tactic]:
                            matrix[tactic].append(technique_id)
        
        for tactic in matrix:
            matrix[tactic] = sorted(matrix[tactic])
        
        return matrix
    
    def get_coverage_report(
        self,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Generate a coverage report showing which tactics/techniques are detected.
        
        Args:
            findings: List of findings
            
        Returns:
            Coverage report
        """
        all_techniques = set()
        all_tactics = set()
        
        for finding in findings:
            all_techniques.update(finding.mitre_techniques)
            all_tactics.update(finding.mitre_tactics)
        
        technique_details = []
        for technique_id in sorted(all_techniques):
            technique = self.technique_database.get(technique_id)
            if technique:
                technique_details.append({
                    "id": technique_id,
                    "name": technique["name"],
                    "tactics": technique["tactic"],
                })
        
        return {
            "total_findings": len(findings),
            "unique_techniques": len(all_techniques),
            "unique_tactics": len(all_tactics),
            "tactics": sorted(list(all_tactics)),
            "techniques": technique_details,
            "matrix": self.generate_attack_matrix(findings),
        }
