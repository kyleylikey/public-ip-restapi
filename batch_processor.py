"""
Batch processing module for IP address lookups
Allows processing multiple IP addresses from files
"""

import json
import csv
import os
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from ip_service import IPService
from database import IPDatabase


class BatchProcessor:
    """Batch processor for multiple IP address lookups"""
    
    def __init__(self, ip_service: IPService = None, database: IPDatabase = None):
        """
        Initialize batch processor
        Args:
            ip_service: IPService instance (creates new if not provided)
            database: IPDatabase instance for storing results
        """
        self.ip_service = ip_service or IPService()
        self.database = database
    
    def process_file(self, file_path: str, output_format: str = 'json',
                     output_file: str = None, store_in_db: bool = False,
                     max_workers: int = 5) -> Tuple[List[Dict], List[Dict]]:
        """
        Process IP addresses from a file
        Args:
            file_path: Path to file containing IP addresses
            output_format: Output format ('json', 'csv')
            output_file: Optional output file path
            store_in_db: Whether to store results in database
            max_workers: Number of concurrent workers
        Returns:
            Tuple of (successful_results, failed_results)
        """
        ip_addresses = self._read_ip_file(file_path)
        
        if not ip_addresses:
            return [], [{'error': 'No IP addresses found in file'}]
        
        return self.process_ips(
            ip_addresses, 
            output_format=output_format,
            output_file=output_file,
            store_in_db=store_in_db,
            max_workers=max_workers
        )
    
    def _read_ip_file(self, file_path: str) -> List[str]:
        """
        Read IP addresses from a file
        Supports txt (one IP per line) and CSV formats
        Args:
            file_path: Path to input file
        Returns:
            List of IP addresses
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        ip_addresses = []
        file_ext = os.path.splitext(file_path)[1].lower()
        
        with open(file_path, 'r') as f:
            if file_ext == '.csv':
                reader = csv.reader(f)
                # Skip header if present
                first_row = next(reader, None)
                if first_row:
                    # Check if first row looks like an IP
                    if self._is_valid_ip_format(first_row[0]):
                        ip_addresses.append(first_row[0].strip())
                    
                for row in reader:
                    if row and row[0].strip():
                        ip_addresses.append(row[0].strip())
            else:
                # Assume txt format - one IP per line
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ip_addresses.append(line)
        
        return ip_addresses
    
    def _is_valid_ip_format(self, ip: str) -> bool:
        """Check if string looks like an IP address"""
        import re
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))
    
    def process_ips(self, ip_addresses: List[str], output_format: str = 'json',
                    output_file: str = None, store_in_db: bool = False,
                    max_workers: int = 5) -> Tuple[List[Dict], List[Dict]]:
        """
        Process a list of IP addresses
        Args:
            ip_addresses: List of IP addresses to lookup
            output_format: Output format ('json', 'csv')
            output_file: Optional output file path
            store_in_db: Whether to store results in database
            max_workers: Number of concurrent workers
        Returns:
            Tuple of (successful_results, failed_results)
        """
        successful = []
        failed = []
        
        # Use ThreadPoolExecutor for concurrent lookups
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self._lookup_ip, ip): ip 
                for ip in ip_addresses
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result, error = future.result()
                    if error:
                        failed.append({'ip': ip, 'error': error})
                    else:
                        successful.append(result)
                        if store_in_db and self.database:
                            self.database.store_lookup(result)
                except Exception as e:
                    failed.append({'ip': ip, 'error': str(e)})
        
        # Export results if output file specified
        if output_file and successful:
            self._export_results(successful, output_file, output_format)
        
        return successful, failed
    
    def _lookup_ip(self, ip_address: str) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Lookup a single IP address
        Args:
            ip_address: IP address to lookup
        Returns:
            Tuple of (result, error)
        """
        return self.ip_service.get_specific_ip_info(ip_address, use_cache=True)
    
    def _export_results(self, results: List[Dict], output_file: str, 
                        output_format: str = 'json'):
        """
        Export results to file
        Args:
            results: List of result dictionaries
            output_file: Output file path
            output_format: Format ('json', 'csv')
        """
        if output_format == 'csv':
            self._export_csv(results, output_file)
        else:
            self._export_json(results, output_file)
    
    def _export_json(self, results: List[Dict], output_file: str):
        """Export results to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def _export_csv(self, results: List[Dict], output_file: str):
        """Export results to CSV file"""
        if not results:
            return
        
        # Get all possible fields from results
        fieldnames = set()
        for result in results:
            fieldnames.update(result.keys())
        fieldnames = sorted(list(fieldnames))
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)


class NetworkAnalyzer:
    """Analyze and compare multiple IP addresses"""
    
    def __init__(self, ip_service: IPService = None):
        """Initialize network analyzer"""
        self.ip_service = ip_service or IPService()
    
    def compare_ips(self, ip_addresses: List[str]) -> Dict:
        """
        Compare multiple IP addresses
        Args:
            ip_addresses: List of IP addresses to compare
        Returns:
            Comparison results dictionary
        """
        results = []
        errors = []
        
        for ip in ip_addresses:
            data, error = self.ip_service.get_specific_ip_info(ip, use_cache=True)
            if error:
                errors.append({'ip': ip, 'error': error})
            else:
                results.append(data)
        
        if len(results) < 2:
            return {
                'error': 'Need at least 2 successful lookups for comparison',
                'successful_lookups': len(results),
                'errors': errors
            }
        
        comparison = {
            'ip_count': len(results),
            'ips': [r.get('ip') for r in results],
            'same_country': self._check_same_value(results, 'country_name'),
            'same_region': self._check_same_value(results, 'region_name'),
            'same_city': self._check_same_value(results, 'city'),
            'same_isp': self._check_same_value(results, 'isp'),
            'same_asn': self._check_same_value(results, 'asn'),
            'countries': self._get_unique_values(results, 'country_name'),
            'regions': self._get_unique_values(results, 'region_name'),
            'cities': self._get_unique_values(results, 'city'),
            'isps': self._get_unique_values(results, 'isp'),
            'asns': self._get_unique_values(results, 'asn'),
            'details': results,
            'errors': errors
        }
        
        # Calculate geographic distance if coordinates available
        if all('latitude' in r and 'longitude' in r for r in results):
            comparison['distances'] = self._calculate_distances(results)
        
        return comparison
    
    def _check_same_value(self, results: List[Dict], key: str) -> bool:
        """Check if all results have the same value for a key"""
        values = [r.get(key) for r in results if r.get(key)]
        return len(set(values)) <= 1
    
    def _get_unique_values(self, results: List[Dict], key: str) -> List:
        """Get unique values for a key across all results"""
        values = [r.get(key) for r in results if r.get(key)]
        return list(set(values))
    
    def _calculate_distances(self, results: List[Dict]) -> List[Dict]:
        """Calculate distances between IP locations"""
        import math
        
        distances = []
        for i, r1 in enumerate(results):
            for r2 in results[i+1:]:
                dist = self._haversine_distance(
                    r1['latitude'], r1['longitude'],
                    r2['latitude'], r2['longitude']
                )
                distances.append({
                    'ip1': r1.get('ip'),
                    'ip2': r2.get('ip'),
                    'distance_km': round(dist, 2)
                })
        
        return distances
    
    def _haversine_distance(self, lat1: float, lon1: float, 
                            lat2: float, lon2: float) -> float:
        """Calculate haversine distance between two coordinates"""
        import math
        
        R = 6371  # Earth's radius in km
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = (math.sin(delta_lat/2)**2 + 
             math.cos(lat1_rad) * math.cos(lat2_rad) * 
             math.sin(delta_lon/2)**2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c
    
    def analyze_ip_range(self, base_ip: str, count: int = 10) -> Dict:
        """
        Analyze a range of IP addresses starting from base_ip
        Args:
            base_ip: Starting IP address (IPv4 only)
            count: Number of IPs to analyze
        Returns:
            Analysis results
        """
        # Parse base IP
        parts = base_ip.split('.')
        if len(parts) != 4:
            return {'error': 'Invalid IPv4 address format'}
        
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return {'error': 'Invalid IPv4 address format'}
        
        # Generate IP range
        ips = []
        for i in range(count):
            ip_int = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3] + i
            new_ip = f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"
            ips.append(new_ip)
        
        return self.compare_ips(ips)
