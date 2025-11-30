"""
Additional data sources module
Integrates multiple IP information APIs for comprehensive data
"""

import requests
import json
from typing import Dict, Optional, Tuple, List
from abc import ABC, abstractmethod


class IPDataSource(ABC):
    """Abstract base class for IP data sources"""
    
    @abstractmethod
    def get_ip_info(self, ip_address: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        """Get IP information from this data source"""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Data source name"""
        pass
    
    @property
    def requires_api_key(self) -> bool:
        """Whether this source requires an API key"""
        return False


class IPAPICoSource(IPDataSource):
    """ipapi.co data source (default)"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://ipapi.co"
        self.timeout = 10
    
    @property
    def name(self) -> str:
        return "ipapi.co"
    
    def get_ip_info(self, ip_address: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        try:
            if ip_address:
                url = f"{self.base_url}/{ip_address}/json/"
            else:
                url = f"{self.base_url}/json/"
            
            if self.api_key:
                url += f"?key={self.api_key}"
            
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if 'error' in data:
                return None, data.get('reason', 'Unknown error')
            
            # Normalize field names
            normalized = {
                'ip': data.get('ip'),
                'type': data.get('version'),
                'country_name': data.get('country_name'),
                'country_code': data.get('country_code'),
                'region_name': data.get('region'),
                'city': data.get('city'),
                'zip': data.get('postal'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone'),
                'isp': data.get('org'),
                'asn': data.get('asn'),
                'source': self.name
            }
            
            return normalized, None
            
        except requests.exceptions.Timeout:
            return None, "Request timeout"
        except requests.exceptions.RequestException as e:
            return None, str(e)
        except Exception as e:
            return None, str(e)


class IPInfoSource(IPDataSource):
    """ipinfo.io data source"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://ipinfo.io"
        self.timeout = 10
    
    @property
    def name(self) -> str:
        return "ipinfo.io"
    
    def get_ip_info(self, ip_address: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        try:
            if ip_address:
                url = f"{self.base_url}/{ip_address}/json"
            else:
                url = f"{self.base_url}/json"
            
            headers = {}
            if self.api_key:
                headers['Authorization'] = f"Bearer {self.api_key}"
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if 'error' in data:
                return None, data.get('error', {}).get('message', 'Unknown error')
            
            # Parse location
            loc = data.get('loc', '').split(',')
            latitude = float(loc[0]) if len(loc) > 0 and loc[0] else None
            longitude = float(loc[1]) if len(loc) > 1 and loc[1] else None
            
            normalized = {
                'ip': data.get('ip'),
                'type': 'IPv4' if '.' in data.get('ip', '') else 'IPv6',
                'country_name': data.get('country'),
                'country_code': data.get('country'),
                'region_name': data.get('region'),
                'city': data.get('city'),
                'zip': data.get('postal'),
                'latitude': latitude,
                'longitude': longitude,
                'timezone': data.get('timezone'),
                'isp': data.get('org'),
                'asn': data.get('org', '').split()[0] if data.get('org') else None,
                'hostname': data.get('hostname'),
                'source': self.name
            }
            
            return normalized, None
            
        except requests.exceptions.Timeout:
            return None, "Request timeout"
        except requests.exceptions.RequestException as e:
            return None, str(e)
        except Exception as e:
            return None, str(e)


class IPAPISource(IPDataSource):
    """ip-api.com data source (free, no API key required)"""
    
    def __init__(self):
        self.base_url = "http://ip-api.com/json"
        self.timeout = 10
    
    @property
    def name(self) -> str:
        return "ip-api.com"
    
    def get_ip_info(self, ip_address: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        try:
            if ip_address:
                url = f"{self.base_url}/{ip_address}"
            else:
                url = self.base_url
            
            # Request additional fields
            url += "?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'fail':
                return None, data.get('message', 'Unknown error')
            
            normalized = {
                'ip': data.get('query'),
                'type': 'IPv4' if '.' in data.get('query', '') else 'IPv6',
                'country_name': data.get('country'),
                'country_code': data.get('countryCode'),
                'region_name': data.get('regionName'),
                'city': data.get('city'),
                'zip': data.get('zip'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp'),
                'asn': data.get('as'),
                'organization': data.get('org'),
                'source': self.name
            }
            
            return normalized, None
            
        except requests.exceptions.Timeout:
            return None, "Request timeout"
        except requests.exceptions.RequestException as e:
            return None, str(e)
        except Exception as e:
            return None, str(e)


class MultiSourceIPLookup:
    """Aggregate IP data from multiple sources"""
    
    def __init__(self, sources: List[IPDataSource] = None):
        """
        Initialize multi-source lookup
        Args:
            sources: List of IPDataSource instances
        """
        if sources:
            self.sources = sources
        else:
            # Default sources
            self.sources = [
                IPAPICoSource(),
                IPAPISource(),
            ]
    
    def add_source(self, source: IPDataSource):
        """Add a data source"""
        self.sources.append(source)
    
    def lookup(self, ip_address: str = None, 
               use_all: bool = False) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Lookup IP information
        Args:
            ip_address: IP address to lookup (None for current IP)
            use_all: If True, queries all sources and merges results
        Returns:
            Tuple of (data, error)
        """
        if use_all:
            return self._lookup_all_sources(ip_address)
        else:
            return self._lookup_first_success(ip_address)
    
    def _lookup_first_success(self, ip_address: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        """Try sources until one succeeds"""
        errors = []
        
        for source in self.sources:
            data, error = source.get_ip_info(ip_address)
            
            if data:
                return data, None
            
            errors.append(f"{source.name}: {error}")
        
        return None, "; ".join(errors)
    
    def _lookup_all_sources(self, ip_address: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        """Query all sources and merge results"""
        results = []
        errors = []
        
        for source in self.sources:
            data, error = source.get_ip_info(ip_address)
            
            if data:
                results.append(data)
            else:
                errors.append(f"{source.name}: {error}")
        
        if not results:
            return None, "; ".join(errors)
        
        # Merge results (first non-None value wins)
        merged = {}
        sources_used = []
        
        # Collect all possible keys
        all_keys = set()
        for result in results:
            all_keys.update(result.keys())
            if 'source' in result:
                sources_used.append(result['source'])
        
        # Merge values
        for key in all_keys:
            if key == 'source':
                continue
            
            for result in results:
                if result.get(key) is not None:
                    merged[key] = result[key]
                    break
        
        merged['sources'] = sources_used
        merged['source_count'] = len(sources_used)
        
        if errors:
            merged['partial_errors'] = errors
        
        return merged, None
    
    def get_source_comparison(self, ip_address: str) -> Dict:
        """
        Compare results from all sources for an IP
        Args:
            ip_address: IP address to lookup
        Returns:
            Comparison of results from each source
        """
        comparison = {
            'ip': ip_address,
            'sources': {},
            'agreement': {},
            'discrepancies': []
        }
        
        results = {}
        for source in self.sources:
            data, error = source.get_ip_info(ip_address)
            
            if data:
                results[source.name] = data
            else:
                results[source.name] = {'error': error}
        
        comparison['sources'] = results
        
        # Check for agreement on key fields
        check_fields = ['country_name', 'city', 'isp', 'timezone']
        
        for field in check_fields:
            values = {}
            for source_name, data in results.items():
                if 'error' not in data and data.get(field):
                    val = data[field]
                    if val not in values:
                        values[val] = []
                    values[val].append(source_name)
            
            if len(values) > 1:
                comparison['discrepancies'].append({
                    'field': field,
                    'values': values
                })
            elif len(values) == 1:
                comparison['agreement'][field] = list(values.keys())[0]
        
        return comparison


class ThreatIntelligence:
    """Basic threat intelligence integration"""
    
    def __init__(self):
        self.known_threats: Dict[str, Dict] = {}
        # Load known threat indicators (in production, this would come from a database or API)
        self._load_threat_data()
    
    def _load_threat_data(self):
        """Load threat intelligence data"""
        # This is a placeholder - in production, this would load from
        # threat intelligence feeds like AbuseIPDB, VirusTotal, etc.
        self.threat_categories = {
            'proxy': 'Proxy/VPN detected',
            'tor': 'Tor exit node',
            'datacenter': 'Datacenter/Hosting IP',
            'spam': 'Known spam source',
            'botnet': 'Known botnet C2',
            'malware': 'Known malware distribution'
        }
    
    def check_ip(self, ip_address: str, ip_data: Dict = None) -> Dict:
        """
        Check IP against threat intelligence
        Args:
            ip_address: IP address to check
            ip_data: Optional existing IP data
        Returns:
            Threat assessment
        """
        assessment = {
            'ip': ip_address,
            'threat_level': 'low',
            'indicators': [],
            'warnings': []
        }
        
        # Check for proxy/VPN/Tor from IP data
        if ip_data:
            if ip_data.get('proxy'):
                assessment['indicators'].append('proxy')
                assessment['warnings'].append('IP is a known proxy')
            
            if ip_data.get('vpn'):
                assessment['indicators'].append('vpn')
                assessment['warnings'].append('IP is a known VPN endpoint')
            
            if ip_data.get('tor'):
                assessment['indicators'].append('tor')
                assessment['warnings'].append('IP is a known Tor exit node')
                assessment['threat_level'] = 'medium'
            
            # Check for datacenter IPs
            isp = ip_data.get('isp', '').lower()
            datacenter_keywords = ['amazon', 'google', 'microsoft', 'digitalocean', 
                                   'linode', 'vultr', 'ovh', 'hetzner']
            
            if any(kw in isp for kw in datacenter_keywords):
                assessment['indicators'].append('datacenter')
                assessment['warnings'].append('IP belongs to a cloud/datacenter provider')
        
        # Set overall threat level
        if len(assessment['indicators']) > 2:
            assessment['threat_level'] = 'high'
        elif len(assessment['indicators']) > 0:
            assessment['threat_level'] = 'medium'
        
        return assessment
    
    def get_reputation_score(self, ip_data: Dict) -> int:
        """
        Calculate a reputation score for an IP (0-100, higher is better)
        Args:
            ip_data: IP information dictionary
        Returns:
            Reputation score
        """
        score = 100
        
        # Deduct points for suspicious indicators
        if ip_data.get('proxy'):
            score -= 20
        if ip_data.get('vpn'):
            score -= 15
        if ip_data.get('tor'):
            score -= 30
        
        # Deduct for datacenter IPs
        isp = ip_data.get('isp', '').lower()
        if any(kw in isp for kw in ['amazon', 'google', 'microsoft', 'digitalocean']):
            score -= 10
        
        return max(0, min(100, score))
