"""
EPSS (Exploit Prediction Scoring System) API Client.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
from typing import Any, Dict, List, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import timed_api_call

logger = logging.getLogger(__name__)


class EPSSClient:
    """
    Client for the EPSS (Exploit Prediction Scoring System) API.
    
    EPSS provides probability scores predicting the likelihood that
    a vulnerability will be exploited in the wild.
    """
    
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or settings.external_api.epss_base_url
        
        self.client = httpx.Client(
            timeout=settings.external_api.request_timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "ShadowHawk-Platform/2.0.0",
            }
        )
        
        # Cache
        self.cache: Dict[str, Dict] = {}
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make an API request with retries."""
        with timed_api_call("epss"):
            response = self.client.get(self.base_url, params=params)
            response.raise_for_status()
            return response.json()
    
    def get_epss_score(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get EPSS score for a specific CVE.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")
        
        Returns:
            EPSS data including score and percentile
        """
        # Normalize CVE ID
        cve_id = cve_id.upper()
        
        # Check cache
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            params = {"cve": cve_id}
            data = self._make_request(params)
            
            epss_data_list = data.get("data", [])
            if epss_data_list:
                epss_data = epss_data_list[0]
                result = {
                    "cve_id": cve_id,
                    "epss_score": float(epss_data.get("epss", 0)),
                    "percentile": float(epss_data.get("percentile", 0)),
                    "date": epss_data.get("date", ""),
                }
                self.cache[cve_id] = result
                return result
            
            return None
        
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"EPSS score not found for {cve_id}")
                return None
            raise
        except Exception as e:
            logger.error(f"Error fetching EPSS score for {cve_id}: {e}")
            raise
    
    def get_epss_scores_batch(
        self, 
        cve_ids: List[str]
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Get EPSS scores for multiple CVEs.
        
        Args:
            cve_ids: List of CVE IDs
        
        Returns:
            Dictionary mapping CVE IDs to EPSS data
        """
        results = {}
        
        # Check cache first
        uncached = []
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            if cve_id in self.cache:
                results[cve_id] = self.cache[cve_id]
            else:
                uncached.append(cve_id)
        
        # Fetch uncached CVEs in batches
        batch_size = 100
        for i in range(0, len(uncached), batch_size):
            batch = uncached[i:i + batch_size]
            
            try:
                params = {"cve": ",".join(batch)}
                data = self._make_request(params)
                
                for epss_data in data.get("data", []):
                    cve_id = epss_data.get("cve", "").upper()
                    result = {
                        "cve_id": cve_id,
                        "epss_score": float(epss_data.get("epss", 0)),
                        "percentile": float(epss_data.get("percentile", 0)),
                        "date": epss_data.get("date", ""),
                    }
                    self.cache[cve_id] = result
                    results[cve_id] = result
                
                # Mark CVEs not in response as not found
                for cve_id in batch:
                    if cve_id not in results:
                        results[cve_id] = None
            
            except Exception as e:
                logger.error(f"Error fetching batch EPSS scores: {e}")
                for cve_id in batch:
                    if cve_id not in results:
                        results[cve_id] = None
        
        return results
    
    def get_scores_by_percentile(
        self, 
        percentile_threshold: float = 0.9,
        date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get CVEs with EPSS scores above a percentile threshold.
        
        Args:
            percentile_threshold: Minimum percentile (0-1)
            date: Optional date filter (YYYY-MM-DD)
        
        Returns:
            List of CVEs with high EPSS scores
        """
        try:
            params: Dict[str, Any] = {
                "percentile-gte": percentile_threshold,
                "order-by": "epss",
                "order": "desc",
            }
            
            if date:
                params["date"] = date
            
            data = self._make_request(params)
            
            results = []
            for epss_data in data.get("data", []):
                results.append({
                    "cve_id": epss_data.get("cve", ""),
                    "epss_score": float(epss_data.get("epss", 0)),
                    "percentile": float(epss_data.get("percentile", 0)),
                    "date": epss_data.get("date", ""),
                })
            
            return results
        
        except Exception as e:
            logger.error(f"Error fetching EPSS scores by percentile: {e}")
            raise
    
    def get_scores_by_range(
        self,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get CVEs with EPSS scores in a specific range.
        
        Args:
            min_score: Minimum EPSS score (0-1)
            max_score: Maximum EPSS score (0-1)
            date: Optional date filter (YYYY-MM-DD)
        
        Returns:
            List of CVEs in the score range
        """
        try:
            params: Dict[str, Any] = {"order-by": "epss", "order": "desc"}
            
            if min_score is not None:
                params["epss-gte"] = min_score
            if max_score is not None:
                params["epss-lte"] = max_score
            if date:
                params["date"] = date
            
            data = self._make_request(params)
            
            results = []
            for epss_data in data.get("data", []):
                results.append({
                    "cve_id": epss_data.get("cve", ""),
                    "epss_score": float(epss_data.get("epss", 0)),
                    "percentile": float(epss_data.get("percentile", 0)),
                    "date": epss_data.get("date", ""),
                })
            
            return results
        
        except Exception as e:
            logger.error(f"Error fetching EPSS scores by range: {e}")
            raise
    
    def interpret_epss_score(self, score: float) -> Dict[str, Any]:
        """
        Provide interpretation of an EPSS score.
        
        Args:
            score: EPSS score (0-1)
        
        Returns:
            Interpretation dictionary
        """
        if score >= 0.9:
            probability = "Very High"
            likelihood = "Exploitation very likely"
            priority = "Critical"
        elif score >= 0.7:
            probability = "High"
            likelihood = "Exploitation likely"
            priority = "High"
        elif score >= 0.4:
            probability = "Medium"
            likelihood = "Exploitation possible"
            priority = "Medium"
        elif score >= 0.1:
            probability = "Low"
            likelihood = "Exploitation less likely"
            priority = "Low"
        else:
            probability = "Very Low"
            likelihood = "Exploitation unlikely"
            priority = "Minimal"
        
        return {
            "score": score,
            "probability_level": probability,
            "likelihood": likelihood,
            "remediation_priority": priority,
        }
    
    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
