#!/usr/bin/env python3
"""
IP Address Information Application
Main entry point for the IP address lookup tool
Provides public IP information with geolocation and network details
"""

import sys
import argparse
import json
from ip_service import IPService
from utils.formatters import IPFormatter
from config import Config
from database import IPDatabase
from batch_processor import BatchProcessor, NetworkAnalyzer
from export_manager import ExportManager

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

New Features:
  %(prog)s --batch ips.txt          # Batch process IPs from file
  %(prog)s --compare 8.8.8.8 1.1.1.1  # Compare multiple IPs
  %(prog)s --history                # Show lookup history
  %(prog)s --export json            # Export history to JSON/CSV/HTML
  %(prog)s --server                 # Start REST API server
  %(prog)s --monitor                # Monitor current IP for changes
  %(prog)s --stats                  # Show database statistics
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
    
    # New feature arguments
    parser.add_argument(
        '--batch',
        metavar='FILE',
        help='Process multiple IPs from a file (one IP per line)'
    )
    parser.add_argument(
        '--compare',
        nargs='+',
        metavar='IP',
        help='Compare multiple IP addresses'
    )
    parser.add_argument(
        '--history',
        action='store_true',
        help='Show lookup history from database'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show database statistics'
    )
    parser.add_argument(
        '--export',
        choices=['json', 'csv', 'html', 'txt'],
        metavar='FORMAT',
        help='Export lookup history to file (json, csv, html, txt)'
    )
    parser.add_argument(
        '--server',
        action='store_true',
        help='Start REST API server'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='API server port (default: 5000)'
    )
    parser.add_argument(
        '--monitor',
        action='store_true',
        help='Monitor current IP for changes'
    )
    parser.add_argument(
        '--monitor-interval',
        type=int,
        default=300,
        help='Monitoring check interval in seconds (default: 300)'
    )
    parser.add_argument(
        '--store',
        action='store_true',
        help='Store lookup result in database'
    )
    parser.add_argument(
        '--search',
        metavar='QUERY',
        help='Search lookup history'
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
        if args.server:
            # Start REST API server
            from api_server import create_app
            api_app = create_app()
            print(f"Starting API server on http://0.0.0.0:{args.port}")
            print("Press Ctrl+C to stop")
            api_app.run(host='0.0.0.0', port=args.port, debug=False)
        
        elif args.batch:
            # Batch process IPs from file
            processor = BatchProcessor(app.ip_service, IPDatabase())
            print(f"Processing IPs from {args.batch}...")
            successful, failed = processor.process_file(
                args.batch, 
                output_format=args.format,
                store_in_db=args.store
            )
            print(f"Completed: {len(successful)} successful, {len(failed)} failed")
            if args.format == 'json':
                print(json.dumps({'successful': successful, 'failed': failed}, indent=2))
        
        elif args.compare:
            # Compare multiple IPs
            analyzer = NetworkAnalyzer(app.ip_service)
            comparison = analyzer.compare_ips(args.compare)
            if args.format == 'json':
                print(json.dumps(comparison, indent=2))
            else:
                print("\n=== IP Comparison Results ===")
                print(f"IPs compared: {', '.join(comparison.get('ips', []))}")
                print(f"Same country: {comparison.get('same_country', False)}")
                print(f"Same city: {comparison.get('same_city', False)}")
                print(f"Same ISP: {comparison.get('same_isp', False)}")
                print(f"\nCountries: {', '.join(comparison.get('countries', []))}")
                print(f"Cities: {', '.join(comparison.get('cities', []))}")
                print(f"ISPs: {', '.join(comparison.get('isps', []))}")
                if 'distances' in comparison:
                    print("\nDistances:")
                    for d in comparison['distances']:
                        print(f"  {d['ip1']} <-> {d['ip2']}: {d['distance_km']} km")
        
        elif args.history:
            # Show lookup history
            db = IPDatabase()
            history = db.get_lookup_history(limit=20)
            if args.format == 'json':
                print(json.dumps(history, indent=2))
            else:
                print("\n=== Recent Lookup History ===")
                for record in history:
                    print(f"  {record.get('lookup_timestamp', 'N/A')} - {record.get('ip_address', 'N/A')} ({record.get('country_name', 'Unknown')})")
        
        elif args.stats:
            # Show database statistics
            db = IPDatabase()
            stats = db.get_statistics()
            if args.format == 'json':
                print(json.dumps(stats, indent=2))
            else:
                print("\n=== Database Statistics ===")
                print(f"Total lookups: {stats.get('total_lookups', 0)}")
                print(f"Unique IPs: {stats.get('unique_ips', 0)}")
                print("\nTop countries:")
                for c in stats.get('top_countries', []):
                    print(f"  {c['country']}: {c['count']}")
        
        elif args.search:
            # Search lookup history
            db = IPDatabase()
            results = db.search_lookups(args.search)
            if args.format == 'json':
                print(json.dumps(results, indent=2))
            else:
                print(f"\n=== Search Results for '{args.search}' ===")
                for record in results:
                    print(f"  {record.get('ip_address', 'N/A')} - {record.get('city', 'Unknown')}, {record.get('country_name', 'Unknown')}")
        
        elif args.export:
            # Export history
            db = IPDatabase()
            history = db.get_lookup_history(limit=1000)
            if not history:
                print("No data to export")
                sys.exit(1)
            
            exporter = ExportManager()
            from datetime import datetime
            filename = f"ip_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            file_path = exporter.export(history, filename, args.export)
            print(f"Exported {len(history)} records to {file_path}")
        
        elif args.monitor:
            # Monitor current IP
            from scheduler import IPMonitor, print_change_notification
            monitor = IPMonitor()
            monitor.add_callback(print_change_notification)
            print(f"Starting IP monitoring (interval: {args.monitor_interval}s)")
            print("Press Ctrl+C to stop")
            monitor.monitor_current_ip(interval_seconds=args.monitor_interval)
        
        elif args.check_connectivity:
            app.check_connectivity()
        elif args.cache_info:
            app.display_cache_info()
        elif args.clear_cache:
            app.clear_cache()
        elif args.ip_address:
            ip_data, error = app.ip_service.get_specific_ip_info(
                args.ip_address,
                use_cache=not args.no_cache
            )
            if error:
                error_output = app.formatter.format_error(f"Failed to retrieve information for {args.ip_address}", error)
                print(error_output)
                sys.exit(1)
            
            if args.store:
                db = IPDatabase()
                db.store_lookup(ip_data)
                print("Stored in database", file=sys.stderr)
            
            app._display_ip_data(ip_data, args.format, f"Information for {args.ip_address}")
        else:
            ip_data, error = app.ip_service.get_current_ip_info(use_cache=not args.no_cache)
            if error:
                error_output = app.formatter.format_error("Failed to retrieve IP information", error)
                print(error_output)
                sys.exit(1)
            
            if args.store:
                db = IPDatabase()
                db.store_lookup(ip_data)
                print("Stored in database", file=sys.stderr)
            
            app._display_ip_data(ip_data, args.format, "Current Public IP Information")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        error_output = IPFormatter.format_error("Application error", str(e))
        print(error_output)
        sys.exit(1)

if __name__ == "__main__":
    main()