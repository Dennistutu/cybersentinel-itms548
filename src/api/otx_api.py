"""
AlienVault OTX (Open Threat Exchange) API Integration
Access threat intelligence pulses and indicators
"""

import requests
import logging
from utils.config import config

logger = logging.getLogger("cybersentinel")

class AlienVaultOTXAPI:
    """AlienVault OTX API client for threat intelligence"""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self):
        self.api_key = config.get_api_key("alienvault_otx")
        self.timeout = config.get("settings.request_timeout", 30)
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                "X-OTX-API-KEY": self.api_key
            })
        
        logger.info("AlienVault OTX API initialized")
    
    def search_pulses(self, query, page=1, limit=10):
        """
        Search for threat intelligence pulses
        
        Args:
            query: Search term (e.g., 'ransomware', 'phishing')
            page: Page number for pagination
            limit: Results per page
            
        Returns:
            List of pulse dictionaries
        """
        if not self.api_key:
            logger.error("AlienVault OTX API key not configured")
            return []
        
        try:
            endpoint = f"{self.BASE_URL}/search/pulses"
            
            params = {
                "q": query,
                "page": page,
                "limit": limit
            }
            
            logger.info(f"Searching OTX pulses for: {query}")
            
            response = self.session.get(
                endpoint,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            results = data.get("results", [])
            pulses = []
            
            for pulse in results:
                pulses.append({
                    "pulse_id": pulse.get("id"),
                    "name": pulse.get("name"),
                    "description": pulse.get("description", "")[:500],
                    "author": pulse.get("author_name"),
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tags": pulse.get("tags", []),
                    "indicator_count": pulse.get("indicator_count", 0),
                    "references": pulse.get("references", [])
                })
            
            logger.info(f"Found {len(pulses)} pulses")
            return pulses
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("OTX API key invalid or expired")
                return []
            else:
                logger.error(f"OTX HTTP error: {e}")
                return []
                
        except Exception as e:
            logger.error(f"OTX search error: {e}")
            return []
    
    def get_pulse_details(self, pulse_id):
        """
        Get detailed information about a specific pulse
        
        Args:
            pulse_id: Pulse ID
            
        Returns:
            Dictionary with pulse details
        """
        if not self.api_key:
            logger.error("AlienVault OTX API key not configured")
            return {}
        
        try:
            endpoint = f"{self.BASE_URL}/pulses/{pulse_id}"
            
            logger.info(f"Fetching pulse details: {pulse_id}")
            
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            return {
                "pulse_id": data.get("id"),
                "name": data.get("name"),
                "description": data.get("description"),
                "author": data.get("author_name"),
                "created": data.get("created"),
                "modified": data.get("modified"),
                "tags": data.get("tags", []),
                "indicators": data.get("indicators", []),
                "references": data.get("references", []),
                "targeted_countries": data.get("targeted_countries", []),
                "malware_families": data.get("malware_families", [])
            }
            
        except Exception as e:
            logger.error(f"Error fetching pulse details: {e}")
            return {}
    
    def get_subscribed_pulses(self, limit=20):
        """
        Get pulses from subscribed users
        
        Args:
            limit: Number of pulses to retrieve
            
        Returns:
            List of pulse dictionaries
        """
        if not self.api_key:
            logger.error("AlienVault OTX API key not configured")
            return []
        
        try:
            endpoint = f"{self.BASE_URL}/pulses/subscribed"
            
            params = {"limit": limit}
            
            logger.info("Fetching subscribed pulses")
            
            response = self.session.get(
                endpoint,
                params=params,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            results = data.get("results", [])
            pulses = []
            
            for pulse in results:
                pulses.append({
                    "pulse_id": pulse.get("id"),
                    "name": pulse.get("name"),
                    "author": pulse.get("author_name"),
                    "created": pulse.get("created"),
                    "indicator_count": pulse.get("indicator_count", 0)
                })
            
            logger.info(f"Retrieved {len(pulses)} subscribed pulses")
            return pulses
            
        except Exception as e:
            logger.error(f"Error fetching subscribed pulses: {e}")
            return []
    
    def check_indicator(self, indicator_type, indicator_value):
        """
        Check if an indicator (IP, domain, hash, etc.) appears in threat intelligence
        
        Args:
            indicator_type: Type of indicator (IPv4, domain, file_hash, etc.)
            indicator_value: The actual indicator value
            
        Returns:
            Dictionary with indicator intelligence
        """
        if not self.api_key:
            logger.error("AlienVault OTX API key not configured")
            return {}
        
        try:
            # Map indicator types to OTX endpoints
            type_map = {
                "ipv4": "IPv4",
                "ipv6": "IPv6",
                "domain": "domain",
                "hostname": "hostname",
                "url": "url",
                "file_hash": "file"
            }
            
            otx_type = type_map.get(indicator_type.lower(), indicator_type)
            endpoint = f"{self.BASE_URL}/indicators/{otx_type}/{indicator_value}/general"
            
            logger.info(f"Checking indicator: {indicator_value}")
            
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            return {
                "indicator": indicator_value,
                "indicator_type": indicator_type,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": data.get("pulse_info", {}).get("pulses", [])[:5],  # First 5 pulses
                "reputation": data.get("reputation", 0)
            }
            
        except Exception as e:
            logger.error(f"Error checking indicator: {e}")
            return {}
    
    def format_pulse_list(self, pulses):
        """
        Format pulse list for display
        
        Args:
            pulses: List of pulse dictionaries
            
        Returns:
            Formatted string
        """
        if not pulses:
            return "No threat intelligence pulses found."
        
        lines = [
            "=" * 60,
            f"THREAT INTELLIGENCE PULSES ({len(pulses)} results)",
            "=" * 60,
            ""
        ]
        
        for i, pulse in enumerate(pulses, 1):
            lines.append(f"[{i}] {pulse.get('name', 'Unnamed Pulse')}")
            lines.append(f"    Author: {pulse.get('author', 'Unknown')}")
            lines.append(f"    Created: {pulse.get('created', 'Unknown')[:10]}")
            lines.append(f"    Indicators: {pulse.get('indicator_count', 0)}")
            
            tags = pulse.get('tags', [])
            if tags:
                lines.append(f"    Tags: {', '.join(tags[:5])}")
            
            description = pulse.get('description', '')
            if description:
                # Truncate long descriptions
                desc_preview = description[:150] + "..." if len(description) > 150 else description
                lines.append(f"    Description: {desc_preview}")
            
            lines.append("")
        
        lines.append("=" * 60)
        return "\n".join(lines)
