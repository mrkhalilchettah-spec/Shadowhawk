"""
MITRE ATT&CK API Client.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import json
import logging
from typing import Any, Dict, List, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import timed_api_call

logger = logging.getLogger(__name__)


class MITREClient:
    """
    Client for MITRE ATT&CK framework data.
    
    Provides access to MITRE ATT&CK tactics, techniques, sub-techniques,
    and their relationships.
    """
    
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or settings.external_api.mitre_attack_url
        
        self.client = httpx.Client(
            timeout=settings.external_api.request_timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "ShadowHawk-Platform/2.0.0",
            }
        )
        
        # Cache for ATT&CK data
        self._attack_data: Optional[Dict] = None
        self._techniques: Dict[str, Dict] = {}
        self._tactics: Dict[str, Dict] = {}
        self._mitigations: Dict[str, Dict] = {}
        self._groups: Dict[str, Dict] = {}
        self._software: Dict[str, Dict] = {}
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _fetch_attack_data(self) -> Dict[str, Any]:
        """Fetch MITRE ATT&CK data from repository."""
        if self._attack_data is not None:
            return self._attack_data
        
        with timed_api_call("mitre"):
            logger.info("Fetching MITRE ATT&CK data...")
            response = self.client.get(self.base_url)
            response.raise_for_status()
            self._attack_data = response.json()
            self._parse_attack_data()
            return self._attack_data
    
    def _parse_attack_data(self) -> None:
        """Parse and index ATT&CK data."""
        if not self._attack_data:
            return
        
        objects = self._attack_data.get("objects", [])
        
        for obj in objects:
            obj_type = obj.get("type")
            obj_id = obj.get("id", "")
            
            if obj_type == "attack-pattern":
                # Check if technique or sub-technique
                if obj.get("x_mitre_is_subtechnique", False):
                    self._techniques[obj_id] = self._parse_technique(obj, is_subtechnique=True)
                else:
                    self._techniques[obj_id] = self._parse_technique(obj, is_subtechnique=False)
            
            elif obj_type == "x-mitre-tactic":
                short_name = obj.get("x_mitre_shortname", "")
                self._tactics[obj_id] = self._parse_tactic(obj)
                # Also index by shortname
                if short_name:
                    self._tactics[short_name] = self._tactics[obj_id]
            
            elif obj_type == "course-of-action":
                self._mitigations[obj_id] = self._parse_mitigation(obj)
            
            elif obj_type == "intrusion-set":
                self._groups[obj_id] = self._parse_group(obj)
            
            elif obj_type == "malware" or obj_type == "tool":
                self._software[obj_id] = self._parse_software(obj)
    
    def _parse_technique(
        self, 
        obj: Dict, 
        is_subtechnique: bool = False
    ) -> Dict[str, Any]:
        """Parse technique data."""
        external_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        
        # Get tactics (kill chain phases)
        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactics = []
        for phase in kill_chain_phases:
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))
        
        # Get platforms
        platforms = obj.get("x_mitre_platforms", [])
        
        # Get data sources
        data_sources = obj.get("x_mitre_data_sources", [])
        
        # Get defenses bypassed
        defenses_bypassed = obj.get("x_mitre_defense_bypassed", [])
        
        # Get permissions required
        permissions_required = obj.get("x_mitre_permissions_required", [])
        
        # Get effective permissions
        effective_permissions = obj.get("x_mitre_effective_permissions", [])
        
        return {
            "id": obj.get("id", ""),
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "url": url,
            "tactics": tactics,
            "is_subtechnique": is_subtechnique,
            "platforms": platforms,
            "data_sources": data_sources,
            "defenses_bypassed": defenses_bypassed,
            "permissions_required": permissions_required,
            "effective_permissions": effective_permissions,
            "version": obj.get("x_mitre_version", ""),
            "modified": obj.get("modified", ""),
            "created": obj.get("created", ""),
        }
    
    def _parse_tactic(self, obj: Dict) -> Dict[str, Any]:
        """Parse tactic data."""
        external_refs = obj.get("external_references", [])
        tactic_id = ""
        url = ""
        
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                tactic_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        
        return {
            "id": obj.get("id", ""),
            "tactic_id": tactic_id,
            "name": obj.get("name", ""),
            "shortname": obj.get("x_mitre_shortname", ""),
            "description": obj.get("description", ""),
            "url": url,
        }
    
    def _parse_mitigation(self, obj: Dict) -> Dict[str, Any]:
        """Parse mitigation data."""
        return {
            "id": obj.get("id", ""),
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
        }
    
    def _parse_group(self, obj: Dict) -> Dict[str, Any]:
        """Parse threat group data."""
        external_refs = obj.get("external_references", [])
        group_id = ""
        
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id", "")
                break
        
        return {
            "id": obj.get("id", ""),
            "group_id": group_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "aliases": obj.get("aliases", []),
        }
    
    def _parse_software(self, obj: Dict) -> Dict[str, Any]:
        """Parse software (malware/tool) data."""
        external_refs = obj.get("external_references", [])
        software_id = ""
        
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                software_id = ref.get("external_id", "")
                break
        
        return {
            "id": obj.get("id", ""),
            "software_id": software_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "type": obj.get("type", ""),
            "platforms": obj.get("x_mitre_platforms", []),
        }
    
    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get technique by MITRE ATT&CK ID.
        
        Args:
            technique_id: Technique ID (e.g., "T1055")
        
        Returns:
            Technique data or None
        """
        self._fetch_attack_data()
        
        # Search by technique_id
        for tech in self._techniques.values():
            if tech.get("technique_id") == technique_id.upper():
                return tech
        
        return None
    
    def get_tactic(self, tactic_shortname: str) -> Optional[Dict[str, Any]]:
        """
        Get tactic by shortname.
        
        Args:
            tactic_shortname: Tactic shortname (e.g., "initial-access")
        
        Returns:
            Tactic data or None
        """
        self._fetch_attack_data()
        return self._tactics.get(tactic_shortname.lower())
    
    def get_all_techniques(self) -> List[Dict[str, Any]]:
        """Get all techniques."""
        self._fetch_attack_data()
        return list(self._techniques.values())
    
    def get_all_tactics(self) -> List[Dict[str, Any]]:
        """Get all tactics."""
        self._fetch_attack_data()
        # Return unique tactics (filter out duplicates from shortname indexing)
        seen = set()
        tactics = []
        for tactic in self._tactics.values():
            if tactic["id"] not in seen:
                seen.add(tactic["id"])
                tactics.append(tactic)
        return tactics
    
    def get_techniques_by_tactic(self, tactic_shortname: str) -> List[Dict[str, Any]]:
        """
        Get all techniques for a specific tactic.
        
        Args:
            tactic_shortname: Tactic shortname
        
        Returns:
            List of techniques
        """
        self._fetch_attack_data()
        
        techniques = []
        for tech in self._techniques.values():
            if tactic_shortname.lower() in [t.lower() for t in tech.get("tactics", [])]:
                techniques.append(tech)
        
        return techniques
    
    def get_subtechniques(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Get all sub-techniques for a technique.
        
        Args:
            technique_id: Parent technique ID (e.g., "T1055")
        
        Returns:
            List of sub-techniques
        """
        self._fetch_attack_data()
        
        subtechniques = []
        for tech in self._techniques.values():
            if tech.get("is_subtechnique"):
                parent_id = tech.get("technique_id", "").split(".")[0]
                if parent_id == technique_id.upper():
                    subtechniques.append(tech)
        
        return subtechniques
    
    def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        """
        Search techniques by name or description.
        
        Args:
            query: Search query
        
        Returns:
            Matching techniques
        """
        self._fetch_attack_data()
        
        query_lower = query.lower()
        matches = []
        
        for tech in self._techniques.values():
            if (query_lower in tech.get("name", "").lower() or
                query_lower in tech.get("description", "").lower() or
                query_lower in tech.get("technique_id", "").lower()):
                matches.append(tech)
        
        return matches
    
    def get_mitigation(self, mitigation_id: str) -> Optional[Dict[str, Any]]:
        """Get mitigation by ID."""
        self._fetch_attack_data()
        return self._mitigations.get(mitigation_id)
    
    def get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        """Get threat group by ID."""
        self._fetch_attack_data()
        
        # Search by group_id
        for group in self._groups.values():
            if group.get("group_id") == group_id.upper():
                return group
        
        return None
    
    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
