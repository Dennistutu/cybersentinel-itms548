"""
VirusTotal API Integration
Scan URLs and files for malware
"""

import requests
import logging
import hashlib
from utils.config import config

logger = logging.getLogger("cybersentinel")

class VirusTotalAPI:
    """VirusTotal API client for URL/file scanning"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self):
        self.api_key = config.get_api_key("virustotal")
        self.timeout = config.get("settings.request_timeout", 30)
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                "x-apikey": self.api_key
            })
        
        logger.info("VirusTotal API initialized")
    
    def scan_url(self, url):
        """
        Scan a URL for malware/phishing
        
        Args:
            url: URL to scan
            
        Returns:
            Dictionary with scan results
        """
        if not self.api_key:
            logger.error("VirusTotal API key not configured")
            return {
                "error": "API key not configured",
                "target": url
            }
        
        try:
            # Submit URL for scanning
            endpoint = f"{self.BASE_URL}/urls"
            
            logger.info(f"Scanning URL: {url}")
            
            response = self.session.post(
                endpoint,
                data={"url": url},
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            # Get analysis ID
            analysis_id = data.get("data", {}).get("id")
            
            if not analysis_id:
                return {"error": "Failed to get analysis ID", "target": url}
            
            # Get scan results
            return self.get_url_report(analysis_id)
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.error("VirusTotal rate limit exceeded")
                return {"error": "Rate limit exceeded (4 requests/minute max)", "target": url}
            else:
                logger.error(f"VirusTotal HTTP error: {e}")
                return {"error": str(e), "target": url}
                
        except Exception as e:
            logger.error(f"VirusTotal scan error: {e}")
            return {"error": str(e), "target": url}
    
    def get_url_report(self, url_id):
        """
        Get URL scan report
        
        Args:
            url_id: URL analysis ID from scan_url()
            
        Returns:
            Dictionary with scan results
        """
        try:
            endpoint = f"{self.BASE_URL}/analyses/{url_id}"
            
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("stats", {})
            
            result = {
                "scan_id": url_id,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_scans": sum(stats.values()),
                "status": attributes.get("status", "unknown"),
                "scan_date": data.get("data", {}).get("attributes", {}).get("date", "")
            }
            
            logger.info(f"Scan results: {result['malicious']}/{result['total_scans']} detected as malicious")
            return result
            
        except Exception as e:
            logger.error(f"Error getting URL report: {e}")
            return {"error": str(e)}
    
    def check_file_hash(self, file_hash):
        """
        Check if a file hash is known to VirusTotal
        
        Args:
            file_hash: SHA-256, SHA-1, or MD5 hash
            
        Returns:
            Dictionary with file reputation
        """
        if not self.api_key:
            logger.error("VirusTotal API key not configured")
            return {
                "error": "API key not configured",
                "target": file_hash
            }
        
        try:
            endpoint = f"{self.BASE_URL}/files/{file_hash}"
            
            logger.info(f"Checking file hash: {file_hash}")
            
            response = self.session.get(endpoint, timeout=self.timeout)
            
            if response.status_code == 404:
                return {
                    "target": file_hash,
                    "found": False,
                    "message": "File hash not found in VirusTotal database"
                }
            
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result = {
                "target": file_hash,
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_scans": sum(stats.values()),
                "file_name": attributes.get("meaningful_name", "Unknown"),
                "file_type": attributes.get("type_description", "Unknown"),
                "size": attributes.get("size", 0),
                "first_seen": attributes.get("first_submission_date", ""),
                "last_analysis": attributes.get("last_analysis_date", "")
            }
            
            logger.info(f"File hash found: {result['malicious']}/{result['total_scans']} malicious")
            return result
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                return {"error": "Rate limit exceeded", "target": file_hash}
            else:
                return {"error": str(e), "target": file_hash}
                
        except Exception as e:
            logger.error(f"Error checking file hash: {e}")
            return {"error": str(e), "target": file_hash}
    
    def format_scan_report(self, scan_data):
        """
        Format scan results for display
        
        Args:
            scan_data: Dictionary from scan_url() or check_file_hash()
            
        Returns:
            Formatted string report
        """
        if "error" in scan_data:
            return f"Error: {scan_data['error']}"
        
        if not scan_data.get("found", True):
            return scan_data.get("message", "No data available")
        
        lines = [
            "=" * 60,
            "VIRUSTOTAL SCAN REPORT",
            "=" * 60,
            f"Target:          {scan_data.get('target', 'N/A')}",
            f"Total Scans:     {scan_data.get('total_scans', 0)}",
            f"Malicious:       {scan_data.get('malicious', 0)}",
            f"Suspicious:      {scan_data.get('suspicious', 0)}",
            f"Undetected:      {scan_data.get('undetected', 0)}",
            f"Harmless:        {scan_data.get('harmless', 0)}",
            "=" * 60,
        ]
        
        # Determine verdict
        malicious = scan_data.get('malicious', 0)
        suspicious = scan_data.get('suspicious', 0)
        
        if malicious > 0 or suspicious > 5:
            verdict = "⚠️  MALICIOUS - Do not trust this file/URL"
        elif suspicious > 0:
            verdict = "⚡ SUSPICIOUS - Exercise caution"
        else:
            verdict = "✅ CLEAN - No threats detected"
        
        lines.append(f"Verdict: {verdict}")
        lines.append("=" * 60)
        
        return "\n".join(lines)
