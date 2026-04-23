"""
AbuseIPDB API Integration
Check IP address reputation and abuse reports
"""

import requests
import logging
from utils.config import config

logger = logging.getLogger("cybersentinel")

class AbuseIPDBAPI:
    """AbuseIPDB API client for IP reputation checks"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self):
        self.api_key = config.get_api_key("abuseipdb")
        self.timeout = config.get("settings.request_timeout", 30)
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                "Key": self.api_key,
                "Accept": "application/json"
            })
        
        logger.info("AbuseIPDB API initialized")
    
    def check_ip(self, ip_address, max_age_days=90, verbose=True):
        """
        Check IP address reputation
        
        Args:
            ip_address: IP address to check
            max_age_days: Maximum age of reports to include
            verbose: Include detailed report data
            
        Returns:
            Dictionary with IP reputation data
        """
        if not self.api_key:
            logger.error("AbuseIPDB API key not configured")
            return {
                "error": "API key not configured",
                "ip_address": ip_address
            }
        
        try:
            endpoint = f"{self.BASE_URL}/check"
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_days,
                "verbose": verbose
            }
            
            logger.info(f"Checking IP: {ip_address}")
            
            response = self.session.get(
                endpoint,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            if "data" in data:
                ip_data = data["data"]
                
                result = {
                    "ip_address": ip_data.get("ipAddress"),
                    "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
                    "country_code": ip_data.get("countryCode", "Unknown"),
                    "usage_type": ip_data.get("usageType", "Unknown"),
                    "isp": ip_data.get("isp", "Unknown"),
                    "domain": ip_data.get("domain", "Unknown"),
                    "is_public": ip_data.get("isPublic", False),
                    "is_whitelisted": ip_data.get("isWhitelisted", False),
                    "total_reports": ip_data.get("totalReports", 0),
                    "num_distinct_users": ip_data.get("numDistinctUsers", 0),
                    "last_reported_at": ip_data.get("lastReportedAt", None)
                }
                
                logger.info(f"IP {ip_address}: Confidence Score = {result['abuse_confidence_score']}%")
                return result
            else:
                logger.warning(f"No data returned for IP: {ip_address}")
                return {"error": "No data available", "ip_address": ip_address}
                
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.error("AbuseIPDB rate limit exceeded")
                return {"error": "Rate limit exceeded. Try again later.", "ip_address": ip_address}
            elif e.response.status_code == 422:
                logger.error(f"Invalid IP address: {ip_address}")
                return {"error": "Invalid IP address format", "ip_address": ip_address}
            else:
                logger.error(f"AbuseIPDB HTTP error: {e}")
                return {"error": str(e), "ip_address": ip_address}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB API error: {e}")
            return {"error": str(e), "ip_address": ip_address}
        except Exception as e:
            logger.error(f"AbuseIPDB parsing error: {e}")
            return {"error": str(e), "ip_address": ip_address}
    
    def get_blacklist(self, confidence_minimum=90, limit=100):
        """
        Get blacklist of reported IPs
        
        Args:
            confidence_minimum: Minimum confidence score (0-100)
            limit: Number of results (max 10000)
            
        Returns:
            List of blacklisted IPs
        """
        if not self.api_key:
            logger.error("AbuseIPDB API key not configured")
            return []
        
        try:
            endpoint = f"{self.BASE_URL}/blacklist"
            
            params = {
                "confidenceMinimum": confidence_minimum,
                "limit": limit
            }
            
            logger.info(f"Fetching blacklist (confidence >= {confidence_minimum}%)")
            
            response = self.session.get(
                endpoint,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            if "data" in data:
                blacklist = data["data"]
                logger.info(f"Retrieved {len(blacklist)} blacklisted IPs")
                return blacklist
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error fetching blacklist: {e}")
            return []
    
    def format_report(self, ip_data):
        """
        Format IP reputation data for display
        
        Args:
            ip_data: Dictionary from check_ip()
            
        Returns:
            Formatted string report
        """
        if "error" in ip_data:
            return f"Error: {ip_data['error']}"
        
        lines = [
            "=" * 60,
            f"IP REPUTATION REPORT",
            "=" * 60,
            f"IP Address:              {ip_data.get('ip_address', 'N/A')}",
            f"Abuse Confidence Score:  {ip_data.get('abuse_confidence_score', 0)}%",
            f"Country:                 {ip_data.get('country_code', 'Unknown')}",
            f"ISP:                     {ip_data.get('isp', 'Unknown')}",
            f"Usage Type:              {ip_data.get('usage_type', 'Unknown')}",
            f"Total Reports:           {ip_data.get('total_reports', 0)}",
            f"Distinct Reporters:      {ip_data.get('num_distinct_users', 0)}",
            f"Whitelisted:             {'Yes' if ip_data.get('is_whitelisted') else 'No'}",
            "=" * 60,
        ]
        
        # Determine status
        score = ip_data.get('abuse_confidence_score', 0)
        if score >= 75:
            status = "⚠️  HIGH RISK - Likely malicious"
        elif score >= 25:
            status = "⚡ MEDIUM RISK - Suspicious activity"
        else:
            status = "✅ LOW RISK - Appears clean"
        
        lines.append(f"Status: {status}")
        lines.append("=" * 60)
        
        return "\n".join(lines)
