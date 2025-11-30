"""
Scheduled monitoring module for tracking IP changes over time
Supports background monitoring and change detection
"""

import time
import threading
import json
import signal
import sys
from datetime import datetime
from typing import Dict, List, Optional, Callable
from ip_service import IPService
from database import IPDatabase


class IPMonitor:
    """Monitor IP addresses for changes over time"""
    
    def __init__(self, ip_service: IPService = None, database: IPDatabase = None):
        """
        Initialize IP monitor
        Args:
            ip_service: IPService instance
            database: IPDatabase instance for persistence
        """
        self.ip_service = ip_service or IPService()
        self.database = database or IPDatabase()
        self._running = False
        self._thread = None
        self._callbacks: List[Callable] = []
        self._last_data: Dict[str, Dict] = {}
    
    def add_callback(self, callback: Callable):
        """
        Add a callback function for change notifications
        Args:
            callback: Function to call when change is detected
        """
        self._callbacks.append(callback)
    
    def notify_change(self, ip_address: str, change_type: str, 
                      old_data: Dict, new_data: Dict):
        """Notify all registered callbacks about a change"""
        for callback in self._callbacks:
            try:
                callback(ip_address, change_type, old_data, new_data)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def check_ip(self, ip_address: str, monitor_id: int = None) -> Dict:
        """
        Check an IP address for changes
        Args:
            ip_address: IP address to check
            monitor_id: Optional database monitor ID
        Returns:
            Check result with change information
        """
        # Get current data
        new_data, error = self.ip_service.get_specific_ip_info(
            ip_address, 
            use_cache=False
        )
        
        if error:
            return {
                'ip': ip_address,
                'success': False,
                'error': error,
                'timestamp': datetime.now().isoformat()
            }
        
        # Store in database
        self.database.store_lookup(new_data)
        
        # Check for changes
        old_data = self._last_data.get(ip_address)
        changes = []
        
        if old_data:
            changes = self._detect_changes(old_data, new_data)
            
            if changes:
                change_type = ', '.join(changes)
                
                # Record change in database
                if monitor_id:
                    self.database.record_change(
                        monitor_id, 
                        old_data, 
                        new_data, 
                        change_type
                    )
                
                # Notify callbacks
                self.notify_change(ip_address, change_type, old_data, new_data)
        
        # Update last known data
        self._last_data[ip_address] = new_data
        
        return {
            'ip': ip_address,
            'success': True,
            'data': new_data,
            'changes': changes,
            'has_changes': len(changes) > 0,
            'timestamp': datetime.now().isoformat()
        }
    
    def _detect_changes(self, old_data: Dict, new_data: Dict) -> List[str]:
        """
        Detect changes between old and new IP data
        Args:
            old_data: Previous lookup data
            new_data: Current lookup data
        Returns:
            List of changed fields
        """
        changes = []
        
        # Fields to monitor for changes
        monitored_fields = [
            'ip', 'country_name', 'country_code', 'region_name', 
            'city', 'isp', 'org', 'asn', 'timezone',
            'proxy', 'vpn', 'tor'
        ]
        
        for field in monitored_fields:
            old_val = old_data.get(field)
            new_val = new_data.get(field)
            
            if old_val != new_val and (old_val or new_val):
                changes.append(f"{field}: {old_val} -> {new_val}")
        
        return changes
    
    def monitor_current_ip(self, interval_seconds: int = 300, 
                           duration_seconds: int = None) -> None:
        """
        Monitor current public IP for changes
        Args:
            interval_seconds: Check interval in seconds
            duration_seconds: Optional duration limit
        """
        print(f"Starting current IP monitoring (interval: {interval_seconds}s)")
        
        start_time = time.time()
        check_count = 0
        
        while True:
            check_count += 1
            print(f"\n[Check #{check_count}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            data, error = self.ip_service.get_current_ip_info(use_cache=False)
            
            if error:
                print(f"  Error: {error}")
            else:
                ip = data.get('ip', 'Unknown')
                location = f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
                print(f"  IP: {ip}")
                print(f"  Location: {location}")
                
                # Check for changes
                old_data = self._last_data.get('current')
                if old_data:
                    changes = self._detect_changes(old_data, data)
                    if changes:
                        print(f"  ⚠️  CHANGES DETECTED:")
                        for change in changes:
                            print(f"      - {change}")
                        self.notify_change('current', 'ip_change', old_data, data)
                    else:
                        print(f"  ✓ No changes")
                
                self._last_data['current'] = data
                self.database.store_lookup(data)
            
            # Check duration limit
            if duration_seconds:
                elapsed = time.time() - start_time
                if elapsed >= duration_seconds:
                    print(f"\nMonitoring duration reached ({duration_seconds}s)")
                    break
            
            time.sleep(interval_seconds)
    
    def start_background_monitoring(self, interval_seconds: int = 300) -> None:
        """
        Start background monitoring thread
        Args:
            interval_seconds: Check interval in seconds
        """
        if self._running:
            print("Monitoring already running")
            return
        
        self._running = True
        
        def monitor_loop():
            while self._running:
                # Get all active monitors from database
                monitors = self.database.get_monitors(active_only=True)
                
                for monitor in monitors:
                    if not self._running:
                        break
                    
                    ip_address = monitor['ip_address']
                    monitor_id = monitor['id']
                    
                    result = self.check_ip(ip_address, monitor_id)
                    
                    if result.get('has_changes'):
                        print(f"[{datetime.now()}] Changes detected for {ip_address}")
                
                # Wait for next interval
                for _ in range(interval_seconds):
                    if not self._running:
                        break
                    time.sleep(1)
        
        self._thread = threading.Thread(target=monitor_loop, daemon=True)
        self._thread.start()
        print(f"Background monitoring started (interval: {interval_seconds}s)")
    
    def stop_background_monitoring(self) -> None:
        """Stop background monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("Background monitoring stopped")
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        monitors = self.database.get_monitors(active_only=True)
        recent_changes = self.database.get_changes(limit=10)
        
        return {
            'is_running': self._running,
            'active_monitors': len(monitors),
            'monitors': monitors,
            'recent_changes': recent_changes,
            'tracked_ips': list(self._last_data.keys())
        }


class ScheduledTask:
    """Simple scheduled task runner"""
    
    def __init__(self):
        self._tasks: Dict[str, Dict] = {}
        self._running = False
        self._thread = None
    
    def add_task(self, task_id: str, func: Callable, 
                 interval_seconds: int, *args, **kwargs) -> None:
        """
        Add a scheduled task
        Args:
            task_id: Unique task identifier
            func: Function to execute
            interval_seconds: Execution interval
            *args, **kwargs: Arguments to pass to function
        """
        self._tasks[task_id] = {
            'func': func,
            'interval': interval_seconds,
            'args': args,
            'kwargs': kwargs,
            'last_run': None,
            'run_count': 0
        }
    
    def remove_task(self, task_id: str) -> bool:
        """Remove a scheduled task"""
        if task_id in self._tasks:
            del self._tasks[task_id]
            return True
        return False
    
    def start(self) -> None:
        """Start the task scheduler"""
        if self._running:
            return
        
        self._running = True
        
        def scheduler_loop():
            while self._running:
                current_time = time.time()
                
                for task_id, task in list(self._tasks.items()):
                    if not self._running:
                        break
                    
                    last_run = task.get('last_run', 0)
                    interval = task['interval']
                    
                    if current_time - last_run >= interval:
                        try:
                            task['func'](*task['args'], **task['kwargs'])
                            task['run_count'] += 1
                        except Exception as e:
                            print(f"Task {task_id} error: {e}")
                        
                        task['last_run'] = current_time
                
                time.sleep(1)
        
        self._thread = threading.Thread(target=scheduler_loop, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """Stop the task scheduler"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def get_status(self) -> Dict:
        """Get scheduler status"""
        def safe_timestamp(ts):
            """Safely convert timestamp to ISO format"""
            if ts is None:
                return None
            try:
                return datetime.fromtimestamp(ts).isoformat()
            except (ValueError, OSError, OverflowError):
                return None
        
        return {
            'running': self._running,
            'task_count': len(self._tasks),
            'tasks': {
                tid: {
                    'interval': t['interval'],
                    'run_count': t['run_count'],
                    'last_run': safe_timestamp(t['last_run'])
                }
                for tid, t in self._tasks.items()
            }
        }


def print_change_notification(ip: str, change_type: str, 
                              old_data: Dict, new_data: Dict):
    """Default change notification handler"""
    print(f"\n{'='*50}")
    print(f"⚠️  IP CHANGE DETECTED")
    print(f"{'='*50}")
    print(f"IP: {ip}")
    print(f"Change Type: {change_type}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")


# CLI entry point for monitoring
def main():
    """Command line monitoring interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='IP Address Monitoring')
    parser.add_argument('--interval', type=int, default=300,
                        help='Check interval in seconds (default: 300)')
    parser.add_argument('--duration', type=int, default=None,
                        help='Monitoring duration in seconds (default: unlimited)')
    parser.add_argument('--ip', type=str, default=None,
                        help='Specific IP to monitor (default: current IP)')
    
    args = parser.parse_args()
    
    # Set up signal handler for graceful shutdown
    monitor = IPMonitor()
    monitor.add_callback(print_change_notification)
    
    def signal_handler(signum, frame):
        print("\nShutting down...")
        monitor.stop_background_monitoring()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if args.ip:
        # Add specific IP to monitor
        monitor.database.add_monitor(args.ip)
        monitor.start_background_monitoring(args.interval)
        
        print(f"Monitoring {args.ip}. Press Ctrl+C to stop.")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
    else:
        # Monitor current IP
        monitor.monitor_current_ip(
            interval_seconds=args.interval,
            duration_seconds=args.duration
        )


if __name__ == '__main__':
    main()
