"""
Utility functions for formatting and displaying IP address information
"""

import json
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

class IPFormatter:
    """Class for formatting IP address information"""
    
    @staticmethod
    def format_ip_info(ip_data, include_geo=True):
        """
        Format IP information into a human-readable string
        Args:
            ip_data: Dictionary containing IP information
            include_geo: Whether to include geolocation information
        Returns:
            Formatted string with IP information
        """
        if not ip_data or 'ip' not in ip_data:
            return f"{Fore.RED}Error: No IP data available{Style.RESET_ALL}"
        
        output = []
        output.append(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        output.append(f"{Fore.YELLOW}IP ADDRESS INFORMATION{Style.RESET_ALL}")
        output.append(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Network Connectivity Information
        output.append(f"\n{Fore.GREEN}Network Connectivity:{Style.RESET_ALL}")
        output.append(f"  IPv4: {Fore.GREEN}Available{Style.RESET_ALL}" if 'ipv4' in ip_data else f"  IPv4: {Fore.RED}Not Available{Style.RESET_ALL}")
        
        # Check if we actually have a real IPv6 address (contains colon)
        has_real_ipv6 = 'ipv6' in ip_data and ':' in ip_data.get('ipv6', '')
        if has_real_ipv6:
            output.append(f"  IPv6: {Fore.GREEN}Available ({ip_data['ipv6']}){Style.RESET_ALL}")
        else:
            output.append(f"  IPv6: {Fore.YELLOW}Not Available (ISP may not support IPv6){Style.RESET_ALL}")

        # Basic IP Information
        output.append(f"\n{Fore.GREEN}Basic Information:{Style.RESET_ALL}")
        output.append(f"  IP Address: {Fore.WHITE}{ip_data.get('ip', 'N/A')}{Style.RESET_ALL}")
        output.append(f"  IP Version: {Fore.WHITE}{ip_data.get('type', 'Unknown')}{Style.RESET_ALL}")
        output.append(f"  Hostname: {Fore.WHITE}{ip_data.get('hostname', 'N/A')}{Style.RESET_ALL}")
        
        if include_geo and any(key in ip_data for key in ['country_name', 'city', 'region_name']):
            output.append(f"\n{Fore.GREEN}Geolocation Information:{Style.RESET_ALL}")
            output.append(f"  Country: {Fore.WHITE}{ip_data.get('country_name', 'N/A')}{Style.RESET_ALL}")
            output.append(f"  Region: {Fore.WHITE}{ip_data.get('region_name', 'N/A')}{Style.RESET_ALL}")
            output.append(f"  City: {Fore.WHITE}{ip_data.get('city', 'N/A')}{Style.RESET_ALL}")
            output.append(f"  ZIP Code: {Fore.WHITE}{ip_data.get('zip', 'N/A')}{Style.RESET_ALL}")
            output.append(f"  Coordinates: {Fore.WHITE}{ip_data.get('latitude', 'N/A')}, {ip_data.get('longitude', 'N/A')}{Style.RESET_ALL}")
        
        # Network Information
        if any(key in ip_data for key in ['asn', 'isp', 'organization']):
            output.append(f"\n{Fore.GREEN}Network Information:{Style.RESET_ALL}")
            output.append(f"  ISP: {Fore.WHITE}{ip_data.get('isp', ip_data.get('organization', 'N/A'))}{Style.RESET_ALL}")
            output.append(f"  ASN: {Fore.WHITE}{ip_data.get('asn', 'N/A')}{Style.RESET_ALL}")
        
        # Security Information
        if any(key in ip_data for key in ['security', 'threat_level']):
            output.append(f"\n{Fore.GREEN}Security Information:{Style.RESET_ALL}")
            output.append(f"  Threat Level: {Fore.WHITE}{ip_data.get('threat_level', 'N/A')}{Style.RESET_ALL}")
            output.append(f"  Is Proxy: {Fore.WHITE}{ip_data.get('proxy', 'N/A')}{Style.RESET_ALL}")
            output.append(f"  Is Tor: {Fore.WHITE}{ip_data.get('tor', 'N/A')}{Style.RESET_ALL}")
        
        output.append(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        output.append(f"{Fore.YELLOW}Data retrieved at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
        return '\n'.join(output)
    
    @staticmethod
    def format_json(ip_data):
        """
        Format IP data as pretty JSON
        Args:
            ip_data: Dictionary containing IP information
        Returns:
            Formatted JSON string
        """
        try:
            return json.dumps(ip_data, indent=2, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            return f"{Fore.RED}Error formatting JSON: {str(e)}{Style.RESET_ALL}"
    
    @staticmethod
    def format_error(error_message, details=None):
        """
        Format error messages consistently
        Args:
            error_message: Main error message
            details: Additional error details
        Returns:
            Formatted error string
        """
        output = []
        output.append(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
        output.append(f"{Fore.RED}ERROR: {error_message}{Style.RESET_ALL}")
        
        if details:
            output.append(f"{Fore.YELLOW}Details: {details}{Style.RESET_ALL}")
        
        output.append(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
        return '\n'.join(output)