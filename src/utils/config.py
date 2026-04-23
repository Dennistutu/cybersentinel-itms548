"""
Configuration management for CyberSentinel
"""

import json
from pathlib import Path
import logging

logger = logging.getLogger("cybersentinel")

class ConfigManager:
    """Manages application configuration"""
    
    def __init__(self):
        self.config_path = Path(__file__).parent.parent.parent / "config" / "config.json"
        self.example_path = Path(__file__).parent.parent.parent / "config" / "config.example.json"
        self.config = self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            if not self.config_path.exists():
                logger.warning(f"Config file not found at {self.config_path}")
                logger.info("Creating default config from example...")
                
                # Load example config
                with open(self.example_path, 'r') as f:
                    config = json.load(f)
                
                # Save as actual config
                self.config_path.parent.mkdir(exist_ok=True)
                with open(self.config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                
                logger.info(f"Config file created. Please add your API keys to: {self.config_path}")
                return config
            
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            logger.info("Configuration loaded successfully")
            return config
            
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self):
        """Return default configuration"""
        return {
            "api_keys": {
                "nvd": "",
                "abuseipdb": "",
                "virustotal": "",
                "alienvault_otx": ""
            },
            "settings": {
                "cache_enabled": True,
                "cache_duration_hours": 24,
                "max_api_retries": 3,
                "request_timeout": 30,
                "log_level": "INFO"
            },
            "database": {
                "path": "data/cybersentinel.db"
            }
        }
    
    def get(self, key, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_api_key(self, service):
        """Get API key for a service"""
        return self.get(f"api_keys.{service}", "")
    
    def save(self):
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info("Configuration saved")
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False

# Global config instance
config = ConfigManager()
