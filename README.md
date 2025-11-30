# IP Address Information Application

A comprehensive Python application for IP address lookup, analysis, and monitoring with REST API support.

## Features

### Core Features
- **Current IP Information**: Get your public IPv4 and IPv6 addresses
- **Geolocation**: Country, city, region, and coordinates
- **Network Details**: ISP information and ASN (Autonomous System Number)
- **Multiple Output Formats**: Human-readable and JSON formats
- **Caching**: Configurable caching to reduce API calls
- **Error Handling**: Comprehensive error handling and retry logic

### New Features
- **Database Integration**: SQLite database for storing historical IP lookups
- **Batch Processing**: Lookup multiple IP addresses from a file
- **Enhanced Security**: Threat intelligence integration for IP reputation
- **Network Analysis**: Compare multiple IP addresses with distance calculation
- **Web Interface**: Built-in web dashboard for easy access
- **REST API**: Full-featured REST API for programmatic access
- **Additional Data Sources**: Support for multiple IP information APIs
- **Export Capabilities**: Export data to CSV, JSON, HTML, or TXT
- **Scheduled Monitoring**: Track IP changes over time with notifications
- **IPv6 Support**: Enhanced IPv6 connectivity checking and information

## Installation

1. Clone or download the application files
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   or
   ```bash
   python3 -m pip install -r requirements.txt
   ```
3. Confirm dependencies installation:
   ```bash
   python3 -m pip list
   ```

## Usage

### Basic Commands

```bash
# Show current IP information
python main.py

# Show current IP in JSON format
python main.py -f json

# Lookup specific IP address
python main.py 8.8.8.8

# Force fresh data (skip cache)
python main.py --no-cache

# Check IPv4/IPv6 connectivity
python main.py --check-connectivity

# Store lookup in database
python main.py --store
python main.py 8.8.8.8 --store
```

### Batch Processing

```bash
# Process multiple IPs from a file
python main.py --batch ips.txt

# With database storage
python main.py --batch ips.txt --store
```

### Network Comparison

```bash
# Compare multiple IP addresses
python main.py --compare 8.8.8.8 1.1.1.1 208.67.222.222

# JSON output
python main.py --compare 8.8.8.8 1.1.1.1 -f json
```

### Database & History

```bash
# Show lookup history
python main.py --history

# Show database statistics
python main.py --stats

# Search lookup history
python main.py --search "United States"
python main.py --search "Google"
```

### Export Data

```bash
# Export to JSON
python main.py --export json

# Export to CSV
python main.py --export csv

# Export to HTML report
python main.py --export html
```

### REST API Server

```bash
# Start API server on default port (5000)
python main.py --server

# Start on custom port
python main.py --server --port 8080

# Or run directly
python api_server.py
```

### IP Monitoring

```bash
# Monitor current IP for changes (default: check every 5 minutes)
python main.py --monitor

# Custom interval (in seconds)
python main.py --monitor --monitor-interval 60
```

## REST API Endpoints

When running the API server, the following endpoints are available:

### IP Lookup
- `GET /api/v1/ip` - Get current public IP
- `GET /api/v1/ip/<ip_address>` - Lookup specific IP
- `POST /api/v1/batch` - Batch lookup (body: `{"ips": ["8.8.8.8", "1.1.1.1"]}`)
- `POST /api/v1/compare` - Compare IPs (body: `{"ips": ["8.8.8.8", "1.1.1.1"]}`)

### Database
- `GET /api/v1/history` - Get lookup history
- `GET /api/v1/statistics` - Get database statistics
- `GET /api/v1/search?q=query` - Search lookups

### Export
- `POST /api/v1/export` - Export data (body: `{"format": "json"}`)

### Monitoring
- `GET /api/v1/monitors` - List IP monitors
- `POST /api/v1/monitors` - Add monitor (body: `{"ip": "8.8.8.8"}`)
- `GET /api/v1/changes` - Get IP change history

### Utilities
- `GET /api/v1/connectivity` - Check IPv4/IPv6 connectivity
- `GET /api/v1/cache` - Get cache info
- `DELETE /api/v1/cache` - Clear cache
- `GET /health` - Health check

## Web Interface

Access the web dashboard at `http://localhost:5000/` when running the API server:

- **Dashboard**: Overview with statistics
- **Lookup**: Interactive IP lookup
- **Batch**: Process multiple IPs
- **Compare**: Compare IP addresses
- **History**: View and search lookup history

## Configuration

Set environment variables or create a `.env` file:

```env
# API Keys (optional - free tier available)
IPAPI_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here

# Database
IP_DATABASE_PATH=ip_history.db

# API Server
API_HOST=0.0.0.0
API_PORT=5000
API_DEBUG=false

# Monitoring
MONITOR_INTERVAL=300
```

## Project Structure

```
├── main.py              # CLI entry point
├── ip_service.py        # Core IP lookup service
├── config.py            # Configuration settings
├── database.py          # SQLite database integration
├── batch_processor.py   # Batch processing & network analysis
├── export_manager.py    # Export capabilities
├── api_server.py        # REST API & web interface
├── scheduler.py         # IP monitoring scheduler
├── data_sources.py      # Multiple API integrations
├── requirements.txt     # Dependencies
└── utils/
    └── formatters.py    # Output formatting
```

## License

MIT License