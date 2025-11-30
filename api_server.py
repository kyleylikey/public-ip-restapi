"""
REST API Server and Web Interface
Exposes IP lookup functionality as REST API endpoints
"""

from flask import Flask, request, jsonify, render_template_string, send_file
import os
import json
from datetime import datetime
from typing import Optional

from ip_service import IPService
from database import IPDatabase
from batch_processor import BatchProcessor, NetworkAnalyzer
from export_manager import ExportManager
from config import Config


def create_app(config: dict = None) -> Flask:
    """
    Create and configure Flask application
    Args:
        config: Optional configuration dictionary
    Returns:
        Configured Flask app
    """
    app = Flask(__name__)
    
    # Apply configuration
    app.config['JSON_SORT_KEYS'] = False
    if config:
        app.config.update(config)
    
    # Initialize services
    ip_service = IPService()
    database = IPDatabase()
    batch_processor = BatchProcessor(ip_service, database)
    network_analyzer = NetworkAnalyzer(ip_service)
    export_manager = ExportManager()
    
    # ===================
    # API Routes
    # ===================
    
    @app.route('/api/v1/ip', methods=['GET'])
    def get_current_ip():
        """Get current public IP information"""
        use_cache = request.args.get('cache', 'true').lower() == 'true'
        store = request.args.get('store', 'false').lower() == 'true'
        
        data, error = ip_service.get_current_ip_info(use_cache=use_cache)
        
        if error:
            return jsonify({'error': error}), 500
        
        if store:
            database.store_lookup(data)
        
        return jsonify({
            'success': True,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/v1/ip/<ip_address>', methods=['GET'])
    def get_ip_info(ip_address: str):
        """Get information for a specific IP address"""
        # Validate IP address format
        import re
        ipv4_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        if not (re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address)):
            return jsonify({'error': 'Invalid IP address format', 'ip': ip_address}), 400
        
        use_cache = request.args.get('cache', 'true').lower() == 'true'
        store = request.args.get('store', 'false').lower() == 'true'
        
        data, error = ip_service.get_specific_ip_info(ip_address, use_cache=use_cache)
        
        if error:
            return jsonify({'error': error, 'ip': ip_address}), 400
        
        if store:
            database.store_lookup(data)
        
        return jsonify({
            'success': True,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/v1/batch', methods=['POST'])
    def batch_lookup():
        """Batch lookup multiple IP addresses"""
        content_type = request.content_type or ''
        
        if 'application/json' in content_type:
            data = request.get_json()
            if not data or 'ips' not in data:
                return jsonify({'error': 'Missing "ips" field in request body'}), 400
            ip_list = data['ips']
        else:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        if not isinstance(ip_list, list):
            return jsonify({'error': '"ips" must be a list'}), 400
        
        if len(ip_list) > 100:
            return jsonify({'error': 'Maximum 100 IPs per batch request'}), 400
        
        store = request.args.get('store', 'false').lower() == 'true'
        
        successful, failed = batch_processor.process_ips(
            ip_list, 
            store_in_db=store
        )
        
        return jsonify({
            'success': True,
            'total': len(ip_list),
            'successful': len(successful),
            'failed': len(failed),
            'results': successful,
            'errors': failed,
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/v1/compare', methods=['POST'])
    def compare_ips():
        """Compare multiple IP addresses"""
        data = request.get_json()
        if not data or 'ips' not in data:
            return jsonify({'error': 'Missing "ips" field in request body'}), 400
        
        ip_list = data['ips']
        if len(ip_list) < 2:
            return jsonify({'error': 'At least 2 IP addresses required for comparison'}), 400
        
        comparison = network_analyzer.compare_ips(ip_list)
        
        return jsonify({
            'success': True,
            'comparison': comparison,
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/v1/history', methods=['GET'])
    def get_history():
        """Get lookup history"""
        ip_filter = request.args.get('ip')
        try:
            limit = min(int(request.args.get('limit', 100)), 1000)
            limit = max(limit, 1)
        except (ValueError, TypeError):
            limit = 100
        
        history = database.get_lookup_history(ip_address=ip_filter, limit=limit)
        
        return jsonify({
            'success': True,
            'count': len(history),
            'history': history
        })
    
    @app.route('/api/v1/statistics', methods=['GET'])
    def get_statistics():
        """Get database statistics"""
        stats = database.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
    
    @app.route('/api/v1/search', methods=['GET'])
    def search_lookups():
        """Search lookup history"""
        query = request.args.get('q', '')
        if not query:
            return jsonify({'error': 'Missing search query parameter "q"'}), 400
        
        results = database.search_lookups(query)
        
        return jsonify({
            'success': True,
            'query': query,
            'count': len(results),
            'results': results
        })
    
    @app.route('/api/v1/export', methods=['POST'])
    def export_data():
        """Export lookup history"""
        data = request.get_json() or {}
        format_type = data.get('format', 'json')
        ip_filter = data.get('ip')
        try:
            limit = min(int(data.get('limit', 1000)), 10000)
            limit = max(limit, 1)
        except (ValueError, TypeError):
            limit = 1000
        
        if format_type not in ['json', 'csv', 'txt', 'html']:
            return jsonify({'error': f'Unsupported format: {format_type}'}), 400
        
        # Get data to export
        history = database.get_lookup_history(ip_address=ip_filter, limit=limit)
        
        if not history:
            return jsonify({'error': 'No data to export'}), 404
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"ip_export_{timestamp}"
        
        # Export to system temp directory with proper permissions
        import tempfile
        temp_dir = tempfile.gettempdir()
        export_subdir = os.path.join(temp_dir, 'ip_exports')
        os.makedirs(export_subdir, exist_ok=True)
        export_manager.output_dir = export_subdir
        
        file_path = export_manager.export(history, filename, format_type)
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"{filename}.{format_type}"
        )
    
    @app.route('/api/v1/monitors', methods=['GET', 'POST'])
    def manage_monitors():
        """Manage IP monitors"""
        if request.method == 'GET':
            active_only = request.args.get('active', 'true').lower() == 'true'
            monitors = database.get_monitors(active_only=active_only)
            return jsonify({
                'success': True,
                'count': len(monitors),
                'monitors': monitors
            })
        
        # POST - Add new monitor
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'error': 'Missing "ip" field'}), 400
        
        monitor_id = database.add_monitor(
            ip_address=data['ip'],
            monitor_name=data.get('name'),
            check_interval=data.get('interval', 60)
        )
        
        return jsonify({
            'success': True,
            'monitor_id': monitor_id,
            'message': f"Monitor added for {data['ip']}"
        }), 201
    
    @app.route('/api/v1/changes', methods=['GET'])
    def get_changes():
        """Get IP change history"""
        monitor_id = request.args.get('monitor_id', type=int)
        limit = request.args.get('limit', 50, type=int)
        
        changes = database.get_changes(monitor_id=monitor_id, limit=limit)
        
        return jsonify({
            'success': True,
            'count': len(changes),
            'changes': changes
        })
    
    @app.route('/api/v1/connectivity', methods=['GET'])
    def check_connectivity():
        """Check IPv4 and IPv6 connectivity"""
        ipv4_data, ipv4_error = ip_service._get_basic_ip_info(ip_version=4)
        ipv6_available, ipv6_message = ip_service.check_ipv6_availability()
        
        return jsonify({
            'success': True,
            'ipv4': {
                'available': ipv4_data is not None,
                'ip': ipv4_data.get('ip') if ipv4_data else None,
                'error': ipv4_error
            },
            'ipv6': {
                'available': ipv6_available,
                'message': ipv6_message
            }
        })
    
    @app.route('/api/v1/cache', methods=['GET', 'DELETE'])
    def manage_cache():
        """Manage application cache"""
        if request.method == 'DELETE':
            ip_service.clear_cache()
            return jsonify({
                'success': True,
                'message': 'Cache cleared'
            })
        
        cache_info = ip_service.get_cache_info()
        return jsonify({
            'success': True,
            'cache': cache_info
        })
    
    # ===================
    # Web Interface Routes
    # ===================
    
    @app.route('/')
    def dashboard():
        """Main dashboard page"""
        return render_template_string(DASHBOARD_HTML)
    
    @app.route('/lookup')
    def lookup_page():
        """IP lookup page"""
        return render_template_string(LOOKUP_HTML)
    
    @app.route('/history')
    def history_page():
        """History page"""
        return render_template_string(HISTORY_HTML)
    
    @app.route('/batch')
    def batch_page():
        """Batch processing page"""
        return render_template_string(BATCH_HTML)
    
    @app.route('/compare')
    def compare_page():
        """Network comparison page"""
        return render_template_string(COMPARE_HTML)
    
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat()
        })
    
    return app


# ===================
# HTML Templates
# ===================

BASE_CSS = """
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
    }
    .navbar {
        background: rgba(0,0,0,0.2);
        padding: 1rem 2rem;
        display: flex;
        align-items: center;
        gap: 2rem;
    }
    .navbar a {
        color: white;
        text-decoration: none;
        font-weight: 500;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        transition: background 0.3s;
    }
    .navbar a:hover { background: rgba(255,255,255,0.2); }
    .navbar a.active { background: rgba(255,255,255,0.3); }
    .logo { font-size: 1.5rem; font-weight: bold; color: white; }
    .container {
        max-width: 1200px;
        margin: 2rem auto;
        padding: 0 1rem;
    }
    .card {
        background: white;
        border-radius: 12px;
        padding: 2rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .card h2 { color: #333; margin-bottom: 1rem; }
    .stat-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
    }
    .stat-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 8px;
        text-align: center;
    }
    .stat-value { font-size: 2rem; font-weight: bold; }
    .stat-label { opacity: 0.9; margin-top: 0.5rem; }
    input[type="text"], textarea {
        width: 100%;
        padding: 0.75rem;
        border: 2px solid #e0e0e0;
        border-radius: 8px;
        font-size: 1rem;
        transition: border-color 0.3s;
    }
    input[type="text"]:focus, textarea:focus {
        outline: none;
        border-color: #667eea;
    }
    button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 8px;
        font-size: 1rem;
        cursor: pointer;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
    .result-box {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 1.5rem;
        margin-top: 1rem;
        font-family: monospace;
        white-space: pre-wrap;
        max-height: 400px;
        overflow-y: auto;
    }
    .form-group { margin-bottom: 1rem; }
    .form-group label { display: block; margin-bottom: 0.5rem; color: #555; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e0e0e0; }
    th { background: #f8f9fa; color: #555; }
    .loading { text-align: center; padding: 2rem; color: #666; }
    .error { color: #dc3545; background: #f8d7da; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
    .success { color: #155724; background: #d4edda; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
</style>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>IP Lookup Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    """ + BASE_CSS + """
</head>
<body>
    <nav class="navbar">
        <span class="logo">🌐 IP Lookup</span>
        <a href="/" class="active">Dashboard</a>
        <a href="/lookup">Lookup</a>
        <a href="/batch">Batch</a>
        <a href="/compare">Compare</a>
        <a href="/history">History</a>
    </nav>
    <div class="container">
        <div class="card">
            <h2>📊 Dashboard</h2>
            <div class="stat-grid" id="stats">
                <div class="stat-card">
                    <div class="stat-value" id="total-lookups">-</div>
                    <div class="stat-label">Total Lookups</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="unique-ips">-</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="current-ip">-</div>
                    <div class="stat-label">Your IP</div>
                </div>
            </div>
        </div>
        <div class="card">
            <h2>🕐 Recent Lookups</h2>
            <table id="recent-table">
                <thead><tr><th>IP Address</th><th>Country</th><th>City</th><th>ISP</th><th>Time</th></tr></thead>
                <tbody id="recent-body"><tr><td colspan="5" class="loading">Loading...</td></tr></tbody>
            </table>
        </div>
        <div class="card">
            <h2>🌍 Top Countries</h2>
            <div id="top-countries" class="loading">Loading...</div>
        </div>
    </div>
    <script>
        async function loadDashboard() {
            try {
                // Load current IP
                const ipRes = await fetch('/api/v1/ip');
                const ipData = await ipRes.json();
                if (ipData.success) {
                    document.getElementById('current-ip').textContent = ipData.data.ip || 'N/A';
                }
                
                // Load statistics
                const statsRes = await fetch('/api/v1/statistics');
                const statsData = await statsRes.json();
                if (statsData.success) {
                    document.getElementById('total-lookups').textContent = statsData.statistics.total_lookups || 0;
                    document.getElementById('unique-ips').textContent = statsData.statistics.unique_ips || 0;
                    
                    // Top countries
                    const countries = statsData.statistics.top_countries || [];
                    if (countries.length > 0) {
                        document.getElementById('top-countries').innerHTML = countries.map(c => 
                            `<span style="margin-right: 1rem;">${c.country}: ${c.count}</span>`
                        ).join('');
                    } else {
                        document.getElementById('top-countries').textContent = 'No data yet';
                    }
                    
                    // Recent lookups
                    const recent = statsData.statistics.recent_lookups || [];
                    if (recent.length > 0) {
                        document.getElementById('recent-body').innerHTML = recent.map(r => 
                            `<tr><td>${r.ip}</td><td>-</td><td>-</td><td>-</td><td>${r.timestamp}</td></tr>`
                        ).join('');
                    } else {
                        document.getElementById('recent-body').innerHTML = '<tr><td colspan="5">No lookups yet. Try the Lookup page!</td></tr>';
                    }
                }
            } catch (e) {
                console.error('Error loading dashboard:', e);
            }
        }
        loadDashboard();
    </script>
</body>
</html>
"""

LOOKUP_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>IP Lookup</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    """ + BASE_CSS + """
</head>
<body>
    <nav class="navbar">
        <span class="logo">🌐 IP Lookup</span>
        <a href="/">Dashboard</a>
        <a href="/lookup" class="active">Lookup</a>
        <a href="/batch">Batch</a>
        <a href="/compare">Compare</a>
        <a href="/history">History</a>
    </nav>
    <div class="container">
        <div class="card">
            <h2>🔍 IP Address Lookup</h2>
            <div class="form-group">
                <label for="ip-input">Enter IP Address (leave empty for your current IP)</label>
                <input type="text" id="ip-input" placeholder="e.g., 8.8.8.8">
            </div>
            <div class="form-group">
                <label><input type="checkbox" id="store-db" checked> Store in database</label>
            </div>
            <button onclick="lookupIP()">Lookup IP</button>
            <div id="result" class="result-box" style="display:none;"></div>
        </div>
        <div class="card">
            <h2>📡 Your Current IP</h2>
            <div id="current-ip-info" class="loading">Loading...</div>
        </div>
    </div>
    <script>
        async function lookupIP() {
            const ip = document.getElementById('ip-input').value.trim();
            const store = document.getElementById('store-db').checked;
            const resultDiv = document.getElementById('result');
            
            resultDiv.style.display = 'block';
            resultDiv.textContent = 'Looking up...';
            
            try {
                const url = ip ? `/api/v1/ip/${ip}?store=${store}` : `/api/v1/ip?store=${store}`;
                const res = await fetch(url);
                const data = await res.json();
                resultDiv.textContent = JSON.stringify(data, null, 2);
            } catch (e) {
                resultDiv.textContent = 'Error: ' + e.message;
            }
        }
        
        async function loadCurrentIP() {
            try {
                const res = await fetch('/api/v1/ip');
                const data = await res.json();
                if (data.success) {
                    const d = data.data;
                    document.getElementById('current-ip-info').innerHTML = `
                        <p><strong>IP:</strong> ${d.ip || 'N/A'}</p>
                        <p><strong>Location:</strong> ${d.city || 'N/A'}, ${d.region_name || ''}, ${d.country_name || 'N/A'}</p>
                        <p><strong>ISP:</strong> ${d.isp || d.org || 'N/A'}</p>
                        <p><strong>Timezone:</strong> ${d.timezone || 'N/A'}</p>
                    `;
                }
            } catch (e) {
                document.getElementById('current-ip-info').textContent = 'Error loading IP info';
            }
        }
        loadCurrentIP();
    </script>
</body>
</html>
"""

BATCH_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Batch IP Lookup</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    """ + BASE_CSS + """
</head>
<body>
    <nav class="navbar">
        <span class="logo">🌐 IP Lookup</span>
        <a href="/">Dashboard</a>
        <a href="/lookup">Lookup</a>
        <a href="/batch" class="active">Batch</a>
        <a href="/compare">Compare</a>
        <a href="/history">History</a>
    </nav>
    <div class="container">
        <div class="card">
            <h2>📋 Batch IP Lookup</h2>
            <div class="form-group">
                <label for="ip-list">Enter IP addresses (one per line)</label>
                <textarea id="ip-list" rows="10" placeholder="8.8.8.8
1.1.1.1
208.67.222.222"></textarea>
            </div>
            <div class="form-group">
                <label><input type="checkbox" id="store-db" checked> Store in database</label>
            </div>
            <button onclick="batchLookup()">Process Batch</button>
            <div id="result" class="result-box" style="display:none;"></div>
        </div>
    </div>
    <script>
        async function batchLookup() {
            const ipText = document.getElementById('ip-list').value.trim();
            const store = document.getElementById('store-db').checked;
            const resultDiv = document.getElementById('result');
            
            if (!ipText) {
                alert('Please enter at least one IP address');
                return;
            }
            
            const ips = ipText.split('\\n').map(ip => ip.trim()).filter(ip => ip);
            
            resultDiv.style.display = 'block';
            resultDiv.textContent = `Processing ${ips.length} IP addresses...`;
            
            try {
                const res = await fetch(`/api/v1/batch?store=${store}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips })
                });
                const data = await res.json();
                resultDiv.textContent = JSON.stringify(data, null, 2);
            } catch (e) {
                resultDiv.textContent = 'Error: ' + e.message;
            }
        }
    </script>
</body>
</html>
"""

COMPARE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Compare IPs</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    """ + BASE_CSS + """
</head>
<body>
    <nav class="navbar">
        <span class="logo">🌐 IP Lookup</span>
        <a href="/">Dashboard</a>
        <a href="/lookup">Lookup</a>
        <a href="/batch">Batch</a>
        <a href="/compare" class="active">Compare</a>
        <a href="/history">History</a>
    </nav>
    <div class="container">
        <div class="card">
            <h2>🔄 Compare IP Addresses</h2>
            <p>Compare location, ISP, and network information for multiple IP addresses.</p>
            <div class="form-group">
                <label for="ip-list">Enter IP addresses to compare (one per line, min 2)</label>
                <textarea id="ip-list" rows="5" placeholder="8.8.8.8
1.1.1.1"></textarea>
            </div>
            <button onclick="compareIPs()">Compare</button>
            <div id="result" class="result-box" style="display:none;"></div>
        </div>
    </div>
    <script>
        async function compareIPs() {
            const ipText = document.getElementById('ip-list').value.trim();
            const resultDiv = document.getElementById('result');
            
            if (!ipText) {
                alert('Please enter at least 2 IP addresses');
                return;
            }
            
            const ips = ipText.split('\\n').map(ip => ip.trim()).filter(ip => ip);
            
            if (ips.length < 2) {
                alert('Please enter at least 2 IP addresses');
                return;
            }
            
            resultDiv.style.display = 'block';
            resultDiv.textContent = 'Comparing IP addresses...';
            
            try {
                const res = await fetch('/api/v1/compare', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips })
                });
                const data = await res.json();
                resultDiv.textContent = JSON.stringify(data, null, 2);
            } catch (e) {
                resultDiv.textContent = 'Error: ' + e.message;
            }
        }
    </script>
</body>
</html>
"""

HISTORY_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Lookup History</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    """ + BASE_CSS + """
</head>
<body>
    <nav class="navbar">
        <span class="logo">🌐 IP Lookup</span>
        <a href="/">Dashboard</a>
        <a href="/lookup">Lookup</a>
        <a href="/batch">Batch</a>
        <a href="/compare">Compare</a>
        <a href="/history" class="active">History</a>
    </nav>
    <div class="container">
        <div class="card">
            <h2>📜 Lookup History</h2>
            <div class="form-group" style="display: flex; gap: 1rem;">
                <input type="text" id="search-input" placeholder="Search by IP, country, city...">
                <button onclick="searchHistory()">Search</button>
                <button onclick="loadHistory()" style="background: #6c757d;">Show All</button>
            </div>
            <div class="form-group" style="margin-top: 1rem;">
                <button onclick="exportData('json')">Export JSON</button>
                <button onclick="exportData('csv')" style="background: #28a745;">Export CSV</button>
                <button onclick="exportData('html')" style="background: #17a2b8;">Export HTML</button>
            </div>
            <table id="history-table">
                <thead><tr><th>ID</th><th>IP Address</th><th>Country</th><th>City</th><th>ISP</th><th>Timestamp</th></tr></thead>
                <tbody id="history-body"><tr><td colspan="6" class="loading">Loading...</td></tr></tbody>
            </table>
        </div>
    </div>
    <script>
        async function loadHistory() {
            try {
                const res = await fetch('/api/v1/history?limit=50');
                const data = await res.json();
                displayHistory(data.history || []);
            } catch (e) {
                document.getElementById('history-body').innerHTML = '<tr><td colspan="6" class="error">Error loading history</td></tr>';
            }
        }
        
        async function searchHistory() {
            const query = document.getElementById('search-input').value.trim();
            if (!query) {
                loadHistory();
                return;
            }
            
            try {
                const res = await fetch(`/api/v1/search?q=${encodeURIComponent(query)}`);
                const data = await res.json();
                displayHistory(data.results || []);
            } catch (e) {
                document.getElementById('history-body').innerHTML = '<tr><td colspan="6" class="error">Error searching</td></tr>';
            }
        }
        
        function displayHistory(history) {
            if (history.length === 0) {
                document.getElementById('history-body').innerHTML = '<tr><td colspan="6">No records found</td></tr>';
                return;
            }
            
            document.getElementById('history-body').innerHTML = history.map(h => `
                <tr>
                    <td>${h.id}</td>
                    <td>${h.ip_address || h.ip || 'N/A'}</td>
                    <td>${h.country_name || 'N/A'}</td>
                    <td>${h.city || 'N/A'}</td>
                    <td>${h.isp || 'N/A'}</td>
                    <td>${h.lookup_timestamp || 'N/A'}</td>
                </tr>
            `).join('');
        }
        
        async function exportData(format) {
            try {
                const res = await fetch('/api/v1/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ format })
                });
                
                if (!res.ok) {
                    const err = await res.json();
                    alert(err.error || 'Export failed');
                    return;
                }
                
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `ip_export.${format}`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
            } catch (e) {
                alert('Export error: ' + e.message);
            }
        }
        
        loadHistory();
    </script>
</body>
</html>
"""


# Entry point for running the server
if __name__ == '__main__':
    app = create_app()
    # Note: debug=False for production. Set API_DEBUG=true in environment for development.
    app.run(host=Config.API_HOST, port=Config.API_PORT, debug=Config.API_DEBUG)
