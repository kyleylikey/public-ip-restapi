"""
Export capabilities module
Export IP data to various formats: CSV, JSON, PDF
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any, Optional


class ExportManager:
    """Manager for exporting IP data to various formats"""
    
    SUPPORTED_FORMATS = ['csv', 'json', 'txt', 'html']
    
    def __init__(self, output_dir: str = None):
        """
        Initialize export manager
        Args:
            output_dir: Default output directory for exports
        """
        self.output_dir = output_dir or os.getcwd()
    
    def export(self, data: Any, filename: str, format: str = 'json') -> str:
        """
        Export data to specified format
        Args:
            data: Data to export (dict or list of dicts)
            filename: Output filename (without extension)
            format: Export format ('csv', 'json', 'txt', 'html')
        Returns:
            Path to exported file
        """
        format = format.lower()
        if format not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {format}. Supported: {self.SUPPORTED_FORMATS}")
        
        # Sanitize filename to prevent path traversal
        import re
        sanitized_filename = re.sub(r'[^\w\-_]', '_', filename)
        sanitized_filename = sanitized_filename.strip('_')
        if not sanitized_filename:
            sanitized_filename = 'export'
        
        # Ensure data is a list
        if isinstance(data, dict):
            data = [data]
        
        # Build full path with sanitized filename
        file_path = os.path.join(self.output_dir, f"{sanitized_filename}.{format}")
        
        if format == 'csv':
            self._export_csv(data, file_path)
        elif format == 'json':
            self._export_json(data, file_path)
        elif format == 'txt':
            self._export_txt(data, file_path)
        elif format == 'html':
            self._export_html(data, file_path)
        
        return file_path
    
    def _export_json(self, data: List[Dict], file_path: str):
        """Export data to JSON format"""
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'count': len(data),
            'data': data
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
    
    def _export_csv(self, data: List[Dict], file_path: str):
        """Export data to CSV format"""
        if not data:
            with open(file_path, 'w') as f:
                f.write('')
            return
        
        # Collect all possible fields
        fieldnames = set()
        for item in data:
            fieldnames.update(item.keys())
        
        # Define preferred field order
        preferred_order = [
            'ip', 'ip_address', 'type', 'ip_version', 'hostname',
            'country_name', 'country_code', 'region_name', 'city', 'zip', 'zip_code',
            'latitude', 'longitude', 'timezone',
            'isp', 'org', 'asn', 'organization',
            'proxy', 'vpn', 'tor', 'is_proxy', 'is_vpn', 'is_tor',
            'lookup_timestamp', 'source'
        ]
        
        # Sort fieldnames with preferred order first
        sorted_fields = []
        for field in preferred_order:
            if field in fieldnames:
                sorted_fields.append(field)
                fieldnames.discard(field)
        sorted_fields.extend(sorted(fieldnames))
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sorted_fields)
            writer.writeheader()
            
            for item in data:
                # Convert complex types to strings
                row = {}
                for key in sorted_fields:
                    value = item.get(key, '')
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value)
                    else:
                        row[key] = value
                writer.writerow(row)
    
    def _export_txt(self, data: List[Dict], file_path: str):
        """Export data to plain text format"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"IP Address Export Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Records: {len(data)}\n")
            f.write("=" * 60 + "\n\n")
            
            for i, item in enumerate(data, 1):
                f.write(f"Record #{i}\n")
                f.write("-" * 40 + "\n")
                
                for key, value in item.items():
                    if value is not None and value != '':
                        f.write(f"  {key}: {value}\n")
                
                f.write("\n")
    
    def _export_html(self, data: List[Dict], file_path: str):
        """Export data to HTML format"""
        html_content = self._generate_html_report(data)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_html_report(self, data: List[Dict]) -> str:
        """Generate HTML report content"""
        # Collect all fields
        all_fields = set()
        for item in data:
            all_fields.update(item.keys())
        
        # Preferred display fields
        display_fields = ['ip', 'country_name', 'city', 'isp', 'asn', 'timezone']
        display_fields = [f for f in display_fields if f in all_fields]
        
        # Build table rows
        table_rows = ""
        for item in data:
            row_cells = "".join(
                f"<td>{self._escape_html(str(item.get(field, '')))}</td>"
                for field in display_fields
            )
            table_rows += f"<tr>{row_cells}</tr>\n"
        
        # Build header
        header_cells = "".join(f"<th>{field.replace('_', ' ').title()}</th>" for field in display_fields)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Address Export Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }}
        .meta {{
            color: #666;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #007bff;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .summary {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: #e9ecef;
            padding: 15px;
            border-radius: 8px;
            min-width: 150px;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }}
        .stat-label {{
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>IP Address Export Report</h1>
        <div class="meta">
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{len(data)}</div>
                <div class="stat-label">Total Records</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(set(item.get('country_name', 'Unknown') for item in data))}</div>
                <div class="stat-label">Countries</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(set(item.get('isp', 'Unknown') for item in data))}</div>
                <div class="stat-label">ISPs</div>
            </div>
        </div>
        <table>
            <thead>
                <tr>{header_cells}</tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return html
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    
    def export_statistics(self, stats: Dict, filename: str, format: str = 'json') -> str:
        """
        Export statistics data
        Args:
            stats: Statistics dictionary
            filename: Output filename
            format: Export format
        Returns:
            Path to exported file
        """
        file_path = os.path.join(self.output_dir, f"{filename}.{format}")
        
        if format == 'json':
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, default=str)
        elif format == 'txt':
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("IP Lookup Statistics Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 40 + "\n\n")
                self._write_stats_txt(f, stats)
        
        return file_path
    
    def _write_stats_txt(self, f, stats: Dict, indent: int = 0):
        """Write statistics to text file recursively"""
        prefix = "  " * indent
        for key, value in stats.items():
            if isinstance(value, dict):
                f.write(f"{prefix}{key}:\n")
                self._write_stats_txt(f, value, indent + 1)
            elif isinstance(value, list):
                f.write(f"{prefix}{key}:\n")
                for item in value:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            f.write(f"{prefix}  - {k}: {v}\n")
                    else:
                        f.write(f"{prefix}  - {item}\n")
            else:
                f.write(f"{prefix}{key}: {value}\n")
