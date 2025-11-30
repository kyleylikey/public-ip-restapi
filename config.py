"""
Configuration settings for the IP Address Application
Centralized configuration for easy maintenance and updates
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

class Config:
    """Application configuration class"""
    
    # API Configuration - Using ipapi.co (correct service)
    API_BASE_URL = "https://ipapi.co"
    
    # ipapi.co doesn't require API key for basic usage (1000 requests/day free)
    # For higher limits, you can use API key from ipapi.co
    API_KEY = os.getenv('IPAPI_API_KEY', '')  # Optional for basic usage
    
    # Additional API keys for other data sources
    IPINFO_API_KEY = os.getenv('IPINFO_API_KEY', '')
    
    # Simple IP detection services (no API key required)
    CHECK_IPV4_URL = "https://api.ipify.org?format=json"
    CHECK_IPV6_URL = "https://api64.ipify.org?format=json"
    
    # Request Configuration
    TIMEOUT = 10  # Request timeout in seconds
    MAX_RETRIES = 3  # Maximum number of retry attempts
    
    # Cache Configuration
    CACHE_DURATION = 300  # Cache duration in seconds (5 minutes)
    
    # Database Configuration
    DATABASE_PATH = os.getenv('IP_DATABASE_PATH', 'ip_history.db')
    
    # API Server Configuration
    API_HOST = os.getenv('API_HOST', '0.0.0.0')
    API_PORT = int(os.getenv('API_PORT', '5000'))
    API_DEBUG = os.getenv('API_DEBUG', 'false').lower() == 'true'
    
    # Monitoring Configuration
    MONITOR_INTERVAL = int(os.getenv('MONITOR_INTERVAL', '300'))  # seconds
    
    # Export Configuration
    EXPORT_DIR = os.getenv('EXPORT_DIR', os.getcwd())
    
    # Display Configuration
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    
    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        if not cls.API_KEY:
            print("Note: No API key provided. Using ipapi.co free tier (1000 requests/day).")
        
        if cls.TIMEOUT <= 0:
            raise ValueError("Timeout must be positive")
        
        if cls.MAX_RETRIES < 0:
            raise ValueError("Max retries cannot be negative")
    
    @classmethod
    def get_api_url(cls, ip_address=None):
        """
        Construct ipapi.co API URL
        Args:
            ip_address: Specific IP to check (None for current IP)
        Returns:
            API URL string
        """
        if ip_address:
            # For specific IP lookup
            url = f"{cls.API_BASE_URL}/{ip_address}/json/"
            if cls.API_KEY:
                url += f"?key={cls.API_KEY}"
            return url
        else:
            # For current IP lookup
            url = f"{cls.API_BASE_URL}/json/"
            if cls.API_KEY:
                url += f"?key={cls.API_KEY}"
            return url