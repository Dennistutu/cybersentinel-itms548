"""
National Vulnerability Database (NVD) API Integration
Retrieves CVE vulnerability data
"""

import requests
import logging
from datetime import datetime
from utils.config import config

logger = logging.getLogger("cybersentinel")

class NVDAPI:
    """NVD API client for CVE data"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        self.api_key = config.get_api_key("nvd")
        self.timeout = config.get("settings.request_timeout", 30)
        self.session = requests.Session()
        
        # Add API key to headers if available
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
        
        logger.info("NVD API initialized")
    
    def search_cves(self, keyword=None, cve_id=None, results_per_page=10):
        """
        Search for CVE vulnerabilities
        
        Args:
            keyword: Keyword to search for
            cve_id: Specific CVE ID (e.g., CVE-2024-1234)
            results_per_page: Number of results to return
            
        Returns:
            List of CVE dictionaries
        """
        try:
            params = {
                "resultsPerPage": results_per_page
            }
            
            if cve_id:
                params["cveId"] = cve_id
            elif keyword:
                params["keywordSearch"] = keyword
            
            logger.info(f"Searching NVD: {keyword or cve_id}")
            
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            results = []
            
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "Unknown")
                
                # Extract description
                descriptions = cve.get("descriptions", [])
                description = descriptions[0].get("value", "No description") if descriptions else "No description"
                
                # Extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity = "UNKNOWN"
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics and metrics[version]:
                        cvss_data = metrics[version][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        break
                
                # Extract dates
                published = cve.get("published", "")
                modified = cve.get("lastModified", "")
                
                results.append({
                    "cve_id": cve_id,
                    "description": description[:500],  # Truncate long descriptions
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "published_date": published,
                    "last_modified": modified
                })
            
            logger.info(f"Found {len(results)} vulnerabilities")
            return results
            
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API error: {e}")
            return []
        except Exception as e:
            logger.error(f"NVD parsing error: {e}")
            return []
    
    def get_recent_cves(self, days=7, results_per_page=20):
        """
        Get recently published CVEs
        
        Args:
            days: Number of days to look back
            results_per_page: Number of results
            
        Returns:
            List of recent CVE dictionaries
        """
        try:
            from datetime import timedelta
            
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                "resultsPerPage": results_per_page
            }
            
            logger.info(f"Fetching CVEs from last {days} days")
            
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            results = []
            
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                results.append({
                    "cve_id": cve.get("id", "Unknown"),
                    "published": cve.get("published", ""),
                    "severity": self._extract_severity(cve)
                })
            
            logger.info(f"Retrieved {len(results)} recent CVEs")
            return results
            
        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {e}")
            return []
    
    def _extract_severity(self, cve):
        """Extract severity from CVE data"""
        metrics = cve.get("metrics", {})
        
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                return cvss_data.get("baseSeverity", "UNKNOWN")
        
        return "UNKNOWN"
