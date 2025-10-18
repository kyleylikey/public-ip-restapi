#!/usr/bin/env python3
"""
IP Address Information Application
Main entry point for the IP address lookup tool
Provides public IP information with geolocation and network details
"""

import sys
import argparse
from ip_service import IPService
from utils.formatters import IPFormatter
from config import Config

class IPAddressApp:
    """Main application class for IP address information lookup"""
    
    def __init__(self):
        """Initialize the application"""
        self.ip_service = IPService()
        self.formatter = IPFormatter()
    
    def display_current_ip(self, output_format: str = 'human', use_cache: bool = True):
        """
        Display current public IP address information
        Args:
            output_format: Output format ('human', 'json')
            use_cache: Whether to use cached data
        """
        print(f"Retrieving current public IP information...", file=sys.stderr)
        
        ip_data, error = self.ip_service.get_current_ip_info(use_cache=use_cache)
        
        if error:
            error_output = self.formatter.format_error("Failed to retrieve IP information", error)
            print(error_output)
            sys.exit(1)
        
        self._display_ip_data(ip_data, output_format, "Current Public IP Information")
    
    def display_specific_ip(self, ip_address: str, output_format: str = 'human', use_cache: bool = True):
        """
        Display information for a specific IP address
        Args:
            ip_address: IP address to lookup
            output_format: Output format ('human', 'json')
            use_cache: Whether to use cached data
        """
        print(f"Looking up information for IP: {ip_address}", file=sys.stderr)
        
        ip_data, error = self.ip_service.get_specific_ip_info(ip_address, use_cache=use_cache)
        
        if error:
            error_output = self.formatter.format_error(f"Failed to retrieve information for {ip_address}", error)
            print(error_output)
            sys.exit(1)
        
        self._display_ip_data(ip_data, output_format, f"Information for {ip_address}")
    
    def _display_ip_data(self, ip_data: dict, output_format: str, title: str):
        """
        Display IP data in the specified format
        Args:
            ip_data: IP information dictionary
            output_format: Output format ('human', 'json')
            title: Display title
        """
        if output_format == 'json':
            json_output = self.formatter.format_json(ip_data)
            print(json_output)
        else:
            formatted_output = self.formatter.format_ip_info(ip_data)
            print(formatted_output)
    
    def display_cache_info(self):
        """Display cache information"""
        cache_info = self.ip_service.get_cache_info()
        print(f"Cache Information:")
        print(f"  Cached items: {cache_info['cached_items']}")
        print(f"  Cache duration: {cache_info['cache_duration']} seconds")
        print(f"  Cached keys: {', '.join(cache_info['cached_keys'])}")
    
    def clear_cache(self):
        """Clear application cache"""
        self.ip_service.clear_cache()
        print("Cache cleared successfully")

    def check_connectivity(self):
        """Check IPv4 and IPv6 connectivity"""
        print("Checking network connectivity...")
        
        # Check IPv4
        ipv4_data, ipv4_error = self.ip_service._get_basic_ip_info(ip_version=4)
        if ipv4_data and 'ip' in ipv4_data:
            print(f"✅ IPv4: Available ({ipv4_data['ip']})")
        else:
            print(f"❌ IPv4: Not available - {ipv4_error}")
        
        # Check IPv6
        ipv6_available, ipv6_message = self.ip_service.check_ipv6_availability()
        if ipv6_available:
            print(f"✅ IPv6: {ipv6_message}")
        else:
            print(f"❌ IPv6: {ipv6_message}")

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description='IP Address Information Application',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Show current IP information
  %(prog)s -f json                  # Show current IP in JSON format
  %(prog)s 8.8.8.8                  # Lookup specific IP address
  %(prog)s --no-cache               # Force fresh data (skip cache)
  %(prog)s --cache-info             # Show cache information
  %(prog)s --clear-cache            # Clear cached data
        """
    )
    
    # Add arguments
    parser.add_argument(
        'ip_address', 
        nargs='?', 
        help='Specific IP address to lookup (optional)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['human', 'json'],
        default='human',
        help='Output format (default: human)'
    )
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Skip cache and fetch fresh data'
    )
    parser.add_argument(
        '--cache-info',
        action='store_true',
        help='Display cache information'
    )
    parser.add_argument(
        '--clear-cache',
        action='store_true',
        help='Clear all cached data'
    )
    parser.add_argument(
        '--check-connectivity',
        action='store_true',
        help='Check IPv4 and IPv6 connectivity'
    )
    parser.add_argument(
        '--api-key',
        help='IPAPI API key (can also be set via IPAPI_API_KEY environment variable)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize application
    app = IPAddressApp()
    
    # Handle API key if provided
    if args.api_key:
        Config.API_KEY = args.api_key
    
    # Execute based on arguments
    try:
        if args.check_connectivity:
            app.check_connectivity()
        elif args.cache_info:
            app.display_cache_info()
        elif args.clear_cache:
            app.clear_cache()
        elif args.ip_address:
            app.display_specific_ip(
                ip_address=args.ip_address,
                output_format=args.format,
                use_cache=not args.no_cache
            )
        else:
            app.display_current_ip(
                output_format=args.format,
                use_cache=not args.no_cache
            )
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        error_output = IPFormatter.format_error("Application error", str(e))
        print(error_output)
        sys.exit(1)

if __name__ == "__main__":
    main()