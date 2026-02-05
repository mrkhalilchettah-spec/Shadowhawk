"""
NVD (National Vulnerability Database) API Client.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import timed_api_call

logger = logging.getLogger(__name__)


class NVDClient:
    """
    Client for the National Vulnerability Database (NVD) API.
    
    Provides access to CVE data, vulnerability information, and
    CPE (Common Platform Enumeration) matching.
    """
    
    def __init__(
        self, 
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        rate_limit_per_second: int = 10
    ):
        self.api_key = api_key or settings.external_api.nvd_api_key
        self.base_url = base_url or settings.external_api.nvd_base_url
        self.rate_limit = rate_limit_per_second
        
        self.client = httpx.Client(
            timeout=settings.external_api.request_timeout,
            headers=self._get_headers()
        )
        
        # Rate limiting
        self.last_request_time = 0.0
        self.min_interval = 1.0 / rate_limit_per_second
        
        # Cache
        self.cache: Dict[str, Any] = {}
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with API key if available."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "ShadowHawk-Platform/2.0.0",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers
    
    def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        
        self.last_request_time = time.time()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _make_request(
        self, 
        endpoint: str, 
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make an API request with retries and rate limiting."""
        self._rate_limit()
        
        with timed_api_call("nvd"):
            url = f"{self.base_url}{endpoint}"
            response = self.client.get(url, params=params)
            response.raise_for_status()
            return response.json()
    
    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific CVE.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")
        
        Returns:
            CVE data dictionary or None if not found
        """
        # Check cache
        cache_key = f"cve:{cve_id}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            params = {"cveId": cve_id}
            data = self._make_request("", params=params)
            
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                cve_data = self._parse_cve_data(vulnerabilities[0])
                self.cache[cache_key] = cve_data
                return cve_data
            
            return None
        
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"CVE {cve_id} not found")
                return None
            raise
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            raise
    
    def search_cves(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        results_per_page: int = 20,
        start_index: int = 0
    ) -> Dict[str, Any]:
        """
        Search for CVEs with various filters.
        
        Args:
            keyword: Keyword to search for
            cpe_name: CPE name to filter by
            cvss_v3_severity: CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)
            pub_start_date: Publication start date
            pub_end_date: Publication end date
            results_per_page: Number of results per page
            start_index: Start index for pagination
        
        Returns:
            Search results with CVE list
        """
        params: Dict[str, Any] = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        
        if keyword:
            params["keywordSearch"] = keyword
        
        if cpe_name:
            params["cpeName"] = cpe_name
        
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity
        
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        try:
            data = self._make_request("", params=params)
            
            vulnerabilities = data.get("vulnerabilities", [])
            parsed_cves = [self._parse_cve_data(v) for v in vulnerabilities]
            
            return {
                "total_results": data.get("totalResults", 0),
                "results_per_page": results_per_page,
                "start_index": start_index,
                "cves": parsed_cves,
            }
        
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            raise
    
    def get_recent_cves(
        self, 
        days: int = 7,
        results_per_page: int = 20
    ) -> Dict[str, Any]:
        """
        Get recently published CVEs.
        
        Args:
            days: Number of days to look back
            results_per_page: Number of results per page
        
        Returns:
            Recent CVEs
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        return self.search_cves(
            pub_start_date=start_date,
            pub_end_date=end_date,
            results_per_page=results_per_page
        )
    
    def _parse_cve_data(self, vulnerability: Dict) -> Dict[str, Any]:
        """Parse CVE data from API response."""
        cve = vulnerability.get("cve", {})
        
        cve_id = cve.get("id", "")
        
        # Description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # CVSS Metrics
        metrics = cve.get("metrics", {})
        cvss_v3 = None
        cvss_v2 = None
        
        if "cvssMetricV31" in metrics:
            cvss_v3 = metrics["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics:
            cvss_v3 = metrics["cvssMetricV30"][0].get("cvssData", {})
        
        if "cvssMetricV2" in metrics:
            cvss_v2 = metrics["cvssMetricV2"][0].get("cvssData", {})
        
        # CPE configurations
        configurations = cve.get("configurations", [])
        affected_products = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected_products.append(cpe_match.get("criteria", ""))
        
        # References
        references = cve.get("references", [])
        ref_urls = [ref.get("url", "") for ref in references]
        
        # Published and modified dates
        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")
        
        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": published,
            "last_modified": last_modified,
            "cvss_v3_score": cvss_v3.get("baseScore") if cvss_v3 else None,
            "cvss_v3_severity": cvss_v3.get("baseSeverity") if cvss_v3 else None,
            "cvss_v2_score": cvss_v2.get("baseScore") if cvss_v2 else None,
            "affected_products": affected_products,
            "references": ref_urls,
            "raw_data": cve,
        }
    
    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
