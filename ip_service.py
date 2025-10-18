"""
Core IP address service functionality
Handles API communication, caching, and data processing
"""

import requests
import time
import json
import sys
from typing import Dict, Optional, Tuple
from config import Config
from utils.formatters import IPFormatter

class IPService:
    """Service class for handling IP address information retrieval"""
    
    def __init__(self):
        """Initialize IP service with cache and configuration"""
        self._cache = {}
        self._cache_timestamps = {}
        self.session = requests.Session()
        
        # Configure session with retry strategy
        self.session.headers.update({
            'User-Agent': 'IP-Address-App/1.0',
            'Accept': 'application/json'
        })
        
        # Validate configuration on initialization
        Config.validate_config()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """
        Check if cached data is still valid
        Args:
            cache_key: Key for cached data
        Returns:
            Boolean indicating if cache is valid
        """
        if cache_key not in self._cache_timestamps:
            return False
        
        cache_age = time.time() - self._cache_timestamps[cache_key]
        return cache_age < Config.CACHE_DURATION
    
    def _make_api_request(self, url: str, retry_count: int = 0) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Make API request with error handling and retry logic
        Args:
            url: API endpoint URL
            retry_count: Current retry attempt number
        Returns:
            Tuple of (data, error_message)
        """
        try:
            response = self.session.get(url, timeout=Config.TIMEOUT)
            response.raise_for_status()  # Raises HTTPError for bad status codes
            
            # Parse JSON response
            data = response.json()
            return data, None
            
        except requests.exceptions.Timeout:
            error_msg = f"Request timeout after {Config.TIMEOUT} seconds"
            if retry_count < Config.MAX_RETRIES:
                return self._make_api_request(url, retry_count + 1)
            return None, error_msg
            
        except requests.exceptions.ConnectionError:
            error_msg = "Connection error - check your internet connection"
            if retry_count < Config.MAX_RETRIES:
                time.sleep(1)  # Wait before retry
                return self._make_api_request(url, retry_count + 1)
            return None, error_msg
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error: {e.response.status_code} - {e.response.reason}"
            
            # Handle specific HTTP status codes
            if e.response.status_code == 401:
                error_msg += " - Invalid API key"
            elif e.response.status_code == 429:
                error_msg += " - Rate limit exceeded"
            elif e.response.status_code == 404:
                error_msg += " - API endpoint not found"
                
            return None, error_msg
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Request exception: {str(e)}"
            return None, error_msg
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response: {str(e)}"
            return None, error_msg
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            return None, error_msg
    
    def get_current_ip_info(self, use_cache: bool = True) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Get current public IP address information
        Args:
            use_cache: Whether to use cached data if available
        Returns:
            Tuple of (ip_data, error_message)
        """
        cache_key = "current_ip_info"
        
        # Check cache first if enabled
        if use_cache and self._is_cache_valid(cache_key):
            return self._cache[cache_key], None
        
        # Determine IP version and get basic IP first
        ipv4_data, ipv4_error = self._get_basic_ip_info(ip_version=4)
        ipv6_data, ipv6_error = self._get_basic_ip_info(ip_version=6)
        
        # Use the available IP address for detailed lookup
        target_ip = None
        if ipv4_data and 'ip' in ipv4_data:
            target_ip = ipv4_data['ip']
        elif ipv6_data and 'ip' in ipv6_data:
            target_ip = ipv6_data['ip']
        
        if not target_ip:
            error_msg = f"Could not determine public IP. IPv4: {ipv4_error}, IPv6: {ipv6_error}"
            return None, error_msg
        
        # Get detailed information using ipapi.co
        detailed_data, detailed_error = self._get_detailed_ip_info(target_ip)
        
        # With ipapi.co, we can still get data even if there's an error (fallback)
        if detailed_error and not detailed_data:
            print(f"Warning: {detailed_error}", file=sys.stderr)
            # Continue with basic data only
        
        # Combine basic and detailed information
        combined_data = {}
        if ipv4_data and 'ip' in ipv4_data:
            combined_data['ipv4'] = ipv4_data['ip']
        if ipv6_data and 'ip' in ipv6_data:
            combined_data['ipv6'] = ipv6_data['ip']
        
        # Use the primary IP (IPv4 preferred, fallback to IPv6)
        combined_data['ip'] = target_ip
        combined_data['type'] = 'IPv4' if ipv4_data and 'ip' in ipv4_data else 'IPv6'
        
        # Merge detailed data from ipapi.co
        if detailed_data:
            # Map ipapi.co field names to our expected field names
            field_mapping = {
                'ip': 'ip',
                'version': 'type',
                'city': 'city',
                'region': 'region_name',
                'country_name': 'country_name',
                'country_code': 'country_code',
                'postal': 'zip',
                'latitude': 'latitude',
                'longitude': 'longitude',
                'timezone': 'timezone',
                'org': 'isp',
                'asn': 'asn',
                'hostname': 'hostname'
            }
            
            for ipapi_field, our_field in field_mapping.items():
                if ipapi_field in detailed_data:
                    combined_data[our_field] = detailed_data[ipapi_field]
            
            # Add security information if available
            for security_field in ['proxy', 'vpn', 'tor', 'relay']:
                if security_field in detailed_data:
                    combined_data[security_field] = detailed_data[security_field]
        
        # Cache the result
        if use_cache:
            self._cache[cache_key] = combined_data
            self._cache_timestamps[cache_key] = time.time()
        
        return combined_data, None
    
    def _get_basic_ip_info(self, ip_version: int = 4) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Get basic IP address using simple services
        Args:
            ip_version: 4 for IPv4, 6 for IPv6
        Returns:
            Tuple of (ip_data, error_message)
        """
        url = Config.CHECK_IPV4_URL if ip_version == 4 else Config.CHECK_IPV6_URL
        
        data, error = self._make_api_request(url)
        if error:
            return None, error
        
        # Standardize response format
        if data and 'ip' in data:
            return {'ip': data['ip'], 'type': f'IPv{ip_version}'}, None
        
        return None, "No IP address in response"
    
    def _get_detailed_ip_info(self, ip_address: str) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Get detailed IP information from ipapi.co
        Args:
            ip_address: IP address to lookup
        Returns:
            Tuple of (detailed_data, error_message)
        """
        url = Config.get_api_url(ip_address)
        data, error = self._make_api_request(url)
        
        if error:
            return None, error
        
        # ipapi.co returns error information in the response
        if data and 'error' in data:
            error_msg = data.get('reason', 'Unknown API error')
            return None, f"API Error: {error_msg}"
        
        # ipapi.co returns boolean values as strings, convert them
        if data:
            # Convert string booleans to actual booleans
            for key in ['proxy', 'vpn', 'tor', 'relay']:
                if key in data and isinstance(data[key], str):
                    data[key] = data[key].lower() == 'true'
        
        return data, None
    
    def get_specific_ip_info(self, ip_address: str, use_cache: bool = True) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Get information for a specific IP address
        Args:
            ip_address: IP address to lookup
            use_cache: Whether to use cached data
        Returns:
            Tuple of (ip_data, error_message)
        """
        if not ip_address:
            return None, "IP address cannot be empty"
        
        cache_key = f"ip_info_{ip_address}"
        
        # Check cache first
        if use_cache and self._is_cache_valid(cache_key):
            return self._cache[cache_key], None
        
        # Get detailed information
        data, error = self._get_detailed_ip_info(ip_address)
        
        if error:
            return None, error
        
        # Cache the result
        if use_cache and data:
            self._cache[cache_key] = data
            self._cache_timestamps[cache_key] = time.time()
        
        return data, error
    
    def check_ipv6_availability(self) -> Tuple[bool, Optional[str]]:
        """
        Check if IPv6 connectivity is available
        Returns:
            Tuple of (is_available, error_message)
        """
        try:
            # Test IPv6 connectivity directly
            ipv6_data, ipv6_error = self._get_basic_ip_info(ip_version=6)
            
            if ipv6_error:
                return False, f"No IPv6 connectivity: {ipv6_error}"
            
            if ipv6_data and 'ip' in ipv6_data:
                ip_address = ipv6_data['ip']
                # Check if it's actually an IPv6 address (contains colons)
                if ':' in ip_address:
                    return True, f"IPv6 available: {ip_address}"
                else:
                    return False, f"IPv6 not available (fallback to IPv4: {ip_address})"
            
            return False, "No IPv6 address detected"
            
        except Exception as e:
            return False, f"IPv6 check failed: {str(e)}"

    def clear_cache(self):
        """Clear all cached data"""
        self._cache.clear()
        self._cache_timestamps.clear()
    
    def get_cache_info(self) -> Dict:
        """Get information about current cache state"""
        return {
            'cached_items': len(self._cache),
            'cache_duration': Config.CACHE_DURATION,
            'cached_keys': list(self._cache.keys())
        }