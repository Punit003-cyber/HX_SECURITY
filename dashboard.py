# dashboard_v5.py - HX SECURITY Advanced Scanner Dashboard (Production-Ready)
# This script is a single, self-contained Flask application.

from flask import Flask, render_template_string, send_file, abort, request
from pathlib import Path
import json
import os
import mimetypes
from datetime import datetime
import sqlite3
from urllib.parse import quote_plus, unquote_plus
from collections import defaultdict
import time
import re

# --- Dependency Check and Fallback ---
try:
    import humanize
except ImportError:
    print("Warning: 'humanize' not installed. Install with 'pip install humanize' for readable file sizes.")
    def humanize_naturalsize(s): return f"{s} bytes" if s else "0 B"
    humanize = type('DummyHumanize', (object,), {'naturalsize': humanize_naturalsize})()

# === CONFIG: ADJUST THESE PATHS FOR YOUR ENVIRONMENT ===
# NOTE: The PROJECT_ROOT must be accurate for file fetching to work.
PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", ".")) 
DEFAULT_RESULTS_SUBPATH = PROJECT_ROOT / "results"
DB_PATH = PROJECT_ROOT / "scanner_meta.db"
BROWSER_DIR_NAME = "Browser_Extraction"
BROWSER_DIR = PROJECT_ROOT / BROWSER_DIR_NAME
COLLECTED_LOGS_PATH = PROJECT_ROOT / "collected_logs" # New source for chart data
COMPANY_NAME = "HX SECURITY"
# ======================================================

# --- Initialization and Path Setup ---

def load_paths():
    """Loads and ensures existence of all necessary directories."""
    results_dir = DEFAULT_RESULTS_SUBPATH
    safe_dir = results_dir / "safe"
    alerts_dir = results_dir / "alerts"
    
    # Create all required paths if they don't exist
    results_dir.mkdir(parents=True, exist_ok=True)
    safe_dir.mkdir(exist_ok=True)
    alerts_dir.mkdir(exist_ok=True)
    BROWSER_DIR.mkdir(exist_ok=True)
    COLLECTED_LOGS_PATH.mkdir(exist_ok=True)

    return {
        'results_dir': results_dir,
        'safe_dir': safe_dir,
        'alerts_dir': alerts_dir,
        'BROWSER_DIR': BROWSER_DIR,
        'DB_PATH': DB_PATH,
        'COLLECTED_LOGS_PATH': COLLECTED_LOGS_PATH,
    }

PATHS = load_paths()
safe_dir = PATHS['safe_dir']
alerts_dir = PATHS['alerts_dir']
BROWSER_DIR = PATHS['BROWSER_DIR']
DB_PATH = PATHS['DB_PATH']
COLLECTED_LOGS_PATH = PATHS['COLLECTED_LOGS_PATH']

app = Flask(__name__)
app.jinja_env.globals.update(quote_plus=quote_plus)

# --- Data Aggregation Helpers ---

def read_json_file(file_path):
    """Safely read a JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def get_dir_stats(path: Path):
    """Calculates file count and total size for a given directory."""
    count = 0
    total_size = 0
    if path.exists() and path.is_dir():
        for p in path.rglob('*'):
            if p.is_file():
                count += 1
                try:
                    total_size += p.stat().st_size
                except FileNotFoundError:
                    pass
    return count, total_size

def get_file_listings(path: Path):
    """Gets a list of file metadata for a directory, recursing into one level of subdirectories."""
    file_list = []
    if path.exists() and path.is_dir():
        for p in path.iterdir():
            if p.is_file() and p.name.endswith('.json'):
                try:
                    stat = p.stat()
                    display_name = p.name 
                    file_list.append({
                        'name': display_name, 
                        'path': str(p),
                        'size': humanize.naturalsize(stat.st_size),
                        'timestamp': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
                except Exception:
                    continue
            elif p.is_dir() and p.name not in ['.', '..']:
                 for sub_p in p.iterdir():
                    if sub_p.is_file() and sub_p.suffix.lower() in ['.json', '.txt', '.log']: 
                        try:
                            stat = sub_p.stat()
                            display_name = f"{p.name}/{sub_p.name}" 
                            file_list.append({
                                'name': display_name, 
                                'path': str(sub_p),
                                'size': humanize.naturalsize(stat.st_size),
                                'timestamp': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            })
                        except Exception:
                            continue
    return sorted(file_list, key=lambda x: x['name'])


# --- 1. PIE CHART: Log Count by Folder Type (COLLECTED_LOGS_PATH) ---
def get_folder_log_stats(base_path: Path):
    """Scans collected_logs for JSON files and aggregates counts by subfolder (Log Type)."""
    log_counts = defaultdict(int)

    if base_path.exists() and base_path.is_dir():
        for sub_dir in base_path.iterdir():
            if sub_dir.is_dir():
                # Count only JSON files recursively within this subfolder
                count = len(list(sub_dir.rglob('*.json')))
                if count > 0:
                    log_type = sub_dir.name.replace('_', ' ').title()
                    log_counts[log_type] = count
    
    # Define consistent colors
    color_map = {
        'System Audit': '#ff00ff',
        'Network Traffic': '#00ffff',
        'Application Error': '#ff3333',
        'Security Event': '#39ff14',
        'Windows': '#fccf00',
        'Linux': '#8a2be2',
        'Misc Logs': '#ffffff',
    }

    pie_chart_data = {
        'labels': list(log_counts.keys()),
        'datasets': [{
            'data': list(log_counts.values()),
            'backgroundColor': [color_map.get(label, '#808080') for label in log_counts.keys()],
            'hoverBackgroundColor': [color_map.get(label, '#9932cc') for label in log_counts.keys()],
            'borderColor': '#0a0a0a',
            'borderWidth': 2
        }]
    }

    return pie_chart_data


# --- 2. LINE CHART: Hourly Log Trend (COLLECTED_LOGS_PATH) ---
def get_hourly_log_trend(base_path: Path):
    """
    Scans collected_logs, extracts the hour of the day (0-23) from JSON content
    or file modification time, and aggregates counts.
    """
    hourly_counts = defaultdict(int)
    for h in range(24): # Initialize all 24 hours to 0
        hourly_counts[h] = 0

    if base_path.exists() and base_path.is_dir():
        for log_file in base_path.rglob('*.json'):
            hour = None
            
            # 1. Try to read a timestamp from the JSON content
            data = read_json_file(log_file)
            if data and isinstance(data, dict):
                timestamp_str = data.get('timestamp') or data.get('time') or data.get('date')
                if timestamp_str:
                    try:
                        # Attempt to parse time from various formats (e.g., '2025-10-22 15:10:00' or '15:10:00')
                        match = re.search(r'(\d{1,2})[hH:](\d{2})[mM:](\d{2})|(\d{1,2}):(\d{2}):(\d{2})', timestamp_str)
                        if match:
                            hour_str = match.group(1) or match.group(4)
                            hour = int(hour_str)
                        elif len(timestamp_str) >= 10:
                            # Try full datetime parse if long enough
                            dt_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            hour = dt_obj.hour
                    except Exception:
                        hour = None
            
            # 2. Fallback to file modification time
            if hour is None:
                try:
                    mtime = log_file.stat().st_mtime
                    hour = datetime.fromtimestamp(mtime).hour
                except Exception:
                    continue # Skip if no time can be determined

            if hour is not None and 0 <= hour <= 23:
                hourly_counts[hour] += 1
                
    # Prepare data for Chart.js
    hours = sorted(hourly_counts.keys())
    counts = [hourly_counts[h] for h in hours]
    
    line_chart_data = {
        'labels': [f'{h:02d}:00' for h in hours],
        'datasets': [{
            'label': 'Logs Generated',
            'data': counts,
            'borderColor': '#00ffff',
            'backgroundColor': '#00ffff33', 
            'borderWidth': 3,
            'pointRadius': 5,
            'fill': True,
            'tension': 0.4
        }]
    }

    return line_chart_data


# --- 3. BAR CHART: Browser Data Stats (BROWSER_DIR) ---
def get_browser_data_stats(base_path: Path):
    """Scans the Browser_Extraction path and aggregates file counts by browser and data type."""
    browser_stats = defaultdict(lambda: defaultdict(int)) # browser -> type -> count
    
    browser_keywords = {
        'Chrome': ['chrome', 'google'],
        'Firefox': ['firefox', 'mozilla'],
        'Edge': ['edge', 'microsoft'],
        'Brave': ['brave'],
        'Unknown': [''], # Default, keep at end
    }
    data_types = ['History', 'Bookmarks', 'Cookies', 'Passwords', 'Downloads', 'Cache', 'Settings']
    
    if base_path.exists() and base_path.is_dir():
        for item in base_path.rglob('*.*'):
            if item.is_file():
                filename = item.name.lower()
                path_parts = [p.lower() for p in item.parts]
                
                # Determine Browser
                browser = 'Unknown'
                for name, keywords in browser_keywords.items():
                    if any(k in filename or k in path_parts for k in keywords):
                        browser = name
                        break
                        
                # Determine Data Type
                data_type = 'Misc'
                for dt in data_types:
                    if dt.lower() in filename:
                        data_type = dt
                        break

                browser_stats[browser][data_type] += 1
                
    # Prepare data for Chart.js Bar Chart (stacked)
    bar_chart_labels = sorted([b for b in browser_stats.keys() if b != 'Unknown']) + ['Unknown']
    all_data_types = sorted(list(set(dt for stats in browser_stats.values() for dt in stats.keys() if dt != 'Misc'))) + ['Misc']
    
    type_color_map = {
        'History': '#00ffff',
        'Bookmarks': '#39ff14',
        'Cookies': '#fccf00',
        'Passwords': '#ff3333',
        'Downloads': '#ff00ff',
        'Cache': '#00aaff',
        'Settings': '#ffffff',
        'Misc': '#800080',
    }
    
    bar_chart_datasets = []
    
    for dt in all_data_types:
        color = type_color_map.get(dt, '#808080')
        data_points = [browser_stats[browser].get(dt, 0) for browser in bar_chart_labels]
        
        bar_chart_datasets.append({
            'label': dt,
            'data': data_points,
            'backgroundColor': color,
            'borderColor': '#0a0a0a',
            'borderWidth': 1
        })
        
    bar_chart_data = {
        'labels': bar_chart_labels,
        'datasets': bar_chart_datasets
    }

    return bar_chart_data

# --- 4. DB Logs Table: (scanner_meta.db) ---
def get_db_data(db_path):
    """Fetches log data from scanner_meta.db and ensures the 'logs' table exists."""
    log_data = []
    db_status = "OK"
    conn = None
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # CRITICAL FIX: Ensure the 'logs' table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                log_type TEXT NOT NULL,
                source TEXT,
                message TEXT
            );
        """)
        conn.commit()

        # Fetch recent logs for the table
        cursor.execute("""
            SELECT timestamp, log_type, source, message 
            FROM logs 
            ORDER BY timestamp DESC 
            LIMIT 100
        """)
        rows = cursor.fetchall()
        
        for row in rows:
            timestamp, log_type, source, message = row
            log_type = log_type.strip().upper() 
            
            log_data.append({
                'timestamp': timestamp,
                'type': log_type,
                'source': source,
                'message': message
            })
            
    except Exception as e:
        db_status = f"ERROR: {e}"
        log_data = []
    finally:
        if conn:
            conn.close()
            
    return log_data, db_status

# --- HTML/Jinja Template Definitions ---

BASE_STYLES = """
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
<style>
    :root {
        --neon-blue: #00ffff;
        --neon-green: #39ff14;
        --neon-red: #ff3333;
        --neon-yellow: #fccf00;
        --dark-bg: #0a0a0a;
        --mid-bg: #1a1a1a;
        --text-light: #ffffff;
    }
    body {
        background-color: var(--dark-bg);
        color: var(--text-light);
        font-family: 'Inter', sans-serif;
    }
    .title-text {
        color: var(--neon-blue);
        text-shadow: 0 0 7px var(--neon-blue), 0 0 15px var(--neon-blue); 
        font-weight: 900;
        text-transform: uppercase;
    }
    .card {
        background-color: var(--mid-bg);
        border: 1px solid var(--neon-blue);
        box-shadow: 0 0 10px rgba(0, 255, 255, 0.2);
        transition: transform 0.3s, box-shadow 0.3s;
        border-radius: 0.5rem;
    }
    .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 255, 255, 0.4);
    }
    .card-header {
        background-color: #000;
        border-bottom: 1px solid var(--neon-blue);
        color: var(--neon-green);
        text-shadow: 0 0 5px var(--neon-green);
        font-weight: 700;
        font-size: 1.1rem;
        border-top-left-radius: 0.5rem;
        border-top-right-radius: 0.5rem;
    }
    .kpi-card {
        border-color: var(--neon-yellow);
        text-align: center;
        padding: 1rem;
    }
    .kpi-value {
        font-size: 2.2rem;
        font-weight: 900;
        color: var(--neon-red);
        text-shadow: 0 0 8px var(--neon-red), 0 0 15px rgba(255, 51, 51, 0.5);
    }
    .kpi-title {
        color: var(--neon-blue);
        font-size: 0.9rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    .list-group-item {
        background-color: #0a0a0a !important;
        border-color: #1a1a1a !important;
        transition: background-color 0.2s;
        border-left: 3px solid transparent !important;
    }
    .list-group-item:hover {
        background-color: #00ffff1a !important;
        border-left: 3px solid var(--neon-blue) !important;
    }
    .list-group-item strong {
        font-weight: 700 !important;
        font-size: 0.95rem; 
    }
    .btn-neon {
        color: var(--neon-blue);
        border-color: var(--neon-blue);
        box-shadow: 0 0 5px var(--neon-blue);
        font-size: 0.9rem;
        font-weight: 600;
    }
    .btn-neon:hover {
        color: var(--dark-bg);
        background-color: var(--neon-blue);
        box-shadow: 0 0 12px var(--neon-blue);
    }
    .log-INFO { color: var(--neon-blue) !important; font-weight: 600; }
    .log-WARNING { color: var(--neon-yellow) !important; font-weight: 600; }
    .log-ERROR, .log-CRITICAL { color: var(--neon-red) !important; font-weight: 700; }
    .chart-container {
        height: 350px;
        width: 100%;
        display: flex;
        justify-content: center;
        align-items: center;
    }
    .chart-message {
        color: var(--neon-yellow);
        text-shadow: 0 0 5px var(--neon-yellow);
        font-weight: 700;
        font-size: 1.2rem;
    }
</style>
"""

DASHBOARD_TMPL = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ COMPANY_NAME }} - Cyber Security Dashboard</title>
    {{ BASE_STYLES | safe }}
</head>
<body>
<div class="container-fluid py-5 px-4">
    <h1 class="title-text border-bottom border-secondary pb-3 mb-5 text-center">
        <i class="fas fa-satellite-dish me-3"></i> _HX_ADVANCED THREAT_MONITORING_CONSOLE
    </h1>

    <!-- KPI ROW -->
    <div class="row mb-5 justify-content-center">
        <div class="col-lg-3 col-md-6 mb-4">
            <div class="card kpi-card bg-mid-bg border-success">
                <div class="kpi-title"><i class="fas fa-layer-group me-1"></i> Total Data Artifacts</div>
                <div class="kpi-value text-success" style="color: var(--neon-green) !important; text-shadow: 0 0 8px var(--neon-green);">{{ total_files }}</div>
                <div class="kpi-title">Total Size: {{ humanize.naturalsize(total_size) }}</div>
            </div>
        </div>
        <div class="col-lg-3 col-md-6 mb-4">
            <div class="card kpi-card bg-mid-bg border-blue">
                <div class="kpi-title"><i class="fas fa-hdd me-1"></i> Unscanned Browser Data</div>
                <div class="kpi-value text-info" style="color: var(--neon-blue) !important; text-shadow: 0 0 8px var(--neon-blue);">{{ browser_files }}</div>
                <div class="kpi-title">Size: {{ humanize.naturalsize(browser_size) }}</div>
            </div>
        </div>
        <div class="col-lg-3 col-md-6 mb-4">
            <div class="card kpi-card bg-mid-bg border-danger">
                <div class="kpi-title"><i class="fas fa-exclamation-triangle me-1"></i> High Priority Alerts</div>
                <div class="kpi-value text-danger" style="color: var(--neon-red) !important; text-shadow: 0 0 8px var(--neon-red);">{{ alert_files }}</div>
                <div class="kpi-title">Size: {{ humanize.naturalsize(alert_size) }}</div>
            </div>
        </div>
        <div class="col-lg-3 col-md-6 mb-4">
            <div class="card kpi-card bg-mid-bg border-warning">
                <div class="kpi-title"><i class="fas fa-lock me-1"></i> Confirmed Safe Files</div>
                <div class="kpi-value text-warning" style="color: var(--neon-yellow) !important; text-shadow: 0 0 8px var(--neon-yellow);">{{ safe_files }}</div>
                <div class="kpi-title">Size: {{ humanize.naturalsize(safe_size) }}</div>
            </div>
        </div>
    </div>

    <!-- CHART ROW 1 (Log Charts) -->
    <div class="row mb-5">
        <div class="col-lg-7 mb-4">
            <div class="card p-3">
                <h5 class="card-header mb-3"><i class="fas fa-clock me-2"></i> Log Activity Time of Day Trend ({{ COLLECTED_LOGS_PATH.name }})</h5>
                <div class="chart-container">
                    <canvas id="logLineChart" style="display:none;"></canvas>
                    <p id="lineChartMessage" class="chart-message"></p>
                </div>
            </div>
        </div>
        <div class="col-lg-5 mb-4">
            <div class="card p-3">
                <h5 class="card-header mb-3"><i class="fas fa-project-diagram me-2"></i> Log Type Distribution by Folder ({{ COLLECTED_LOGS_PATH.name }})</h5>
                <div class="chart-container">
                    <canvas id="logPieChart" style="display:none;"></canvas>
                    <p id="pieChartMessage" class="chart-message"></p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- CHART ROW 2 (Browser Chart) -->
    <div class="row mb-5">
        <div class="col-12">
            <div class="card p-3">
                <h5 class="card-header mb-3"><i class="fas fa-chart-bar me-2"></i> Browser Data Extraction Metrics ({{ BROWSER_DIR_NAME }})</h5>
                <div class="chart-container" style="height: 450px;">
                    <canvas id="browserBarChart" style="display:none;"></canvas>
                    <p id="barChartMessage" class="chart-message"></p>
                </div>
            </div>
        </div>
    </div>

    <!-- DB LOG TABLE -->
    <div class="card mb-5">
        <h5 class="card-header d-flex justify-content-between align-items-center">
            <span><i class="fas fa-database me-2"></i> Latest Scanner Logs (scanner_meta.db)</span>
            <span class="badge bg-dark rounded-pill" style="border:1px solid {{ 'var(--neon-green)' if db_status == 'OK' else 'var(--neon-red)' }}; color: {{ 'var(--neon-green)' if db_status == 'OK' else 'var(--neon-red)' }}!important; text-shadow: 0 0 2px {{ 'var(--neon-green)' if db_status == 'OK' else 'var(--neon-red)' }}">
                DB Status: {{ db_status }}
            </span>
        </h5>
        <div class="table-responsive">
            <table class="table table-dark table-striped table-hover mb-0">
                <thead>
                    <tr>
                        <th scope="col" style="width:15%;" class="log-INFO">Timestamp</th>
                        <th scope="col" style="width:10%;" class="log-INFO">Type</th>
                        <th scope="col" style="width:15%;" class="log-INFO">Source</th>
                        <th scope="col" style="width:60%;" class="log-INFO">Message</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in log_data %}
                    <tr>
                        <td><small class="text-white">{{ log.timestamp }}</small></td>
                        <td class="log-{{ log.type }}">{{ log.type }}</td>
                        <td><small class="text-white">{{ log.source }}</small></td>
                        <td><small class="text-white">{{ log.message }}</small></td>
                    </tr>
                    {% endfor %}
                    {% if not log_data %}
                        <tr>
                            <td colspan="4" class="text-center text-warning pt-4 pb-4">
                                <i class="fas fa-sync fa-spin me-2" style="color:var(--neon-blue);"></i> 
                                {% if db_status == 'OK' %}
                                    Awaiting Live Data. Database is initialized but empty.
                                {% else %}
                                    Database Access Failed: {{ db_status }}.
                                {% endif %}
                            </td>
                        </tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- FILE LISTING ROW (BROWSER, ALERTS, SAFE) -->
    <div class="row">
        <div class="col-lg-4 mb-4">
            <div class="card">
                <h5 class="card-header"><i class="fas fa-user-secret me-2"></i> {{ BROWSER_DIR_NAME }} ({{ browser_files }} files)</h5>
                <ul class="list-group list-group-flush" style="max-height: 400px; overflow-y: auto;">
                    {% for file in file_tree['browser'] %}
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <div class="text-truncate" style="flex-grow: 1; margin-right: 10px;">
                            <strong class="log-INFO">{{ file.name }}</strong>
                            <small class="text-white-50 d-block">({{ file.size }} | {{ file.timestamp }})</small>
                        </div>
                        <a href="{{ url_for('view_file', path=quote_plus(file.path)) }}" class="btn btn-sm btn-neon">View <i class="fas fa-arrow-right"></i></a>
                    </li>
                    {% endfor %}
                    {% if not file_tree['browser'] %}<li class="list-group-item text-warning">No browser extraction files found. Check path.</li>{% endif %}
                </ul>
            </div>
        </div>
        <div class="col-lg-4 mb-4">
            <div class="card border-danger">
                <h5 class="card-header text-danger" style="color:var(--neon-red)!important; text-shadow:0 0 5px var(--neon-red);"><i class="fas fa-radiation-alt me-2"></i> Alerts/Malicious ({{ alert_files }} files)</h5>
                <ul class="list-group list-group-flush" style="max-height: 400px; overflow-y: auto;">
                    {% for file in file_tree['alerts'] %}
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <div class="text-truncate" style="flex-grow: 1; margin-right: 10px;">
                            <strong class="log-ERROR">{{ file.name }}</strong>
                            <small class="text-white-50 d-block">({{ file.size }} | {{ file.timestamp }})</small>
                        </div>
                        <a href="{{ url_for('view_file', path=quote_plus(file.path)) }}" class="btn btn-sm btn-neon border-danger text-danger" style="color:var(--neon-red); border-color:var(--neon-red); box-shadow: 0 0 5px var(--neon-red);">View <i class="fas fa-skull-crossbones"></i></a>
                    </li>
                    {% endfor %}
                    {% if not file_tree['alerts'] %}<li class="list-group-item text-warning">No alert files found. Check path.</li>{% endif %}
                </ul>
            </div>
        </div>
        <div class="col-lg-4 mb-4">
            <div class="card border-success">
                <h5 class="card-header text-success" style="color:var(--neon-green)!important; text-shadow:0 0 5px var(--neon-green);"><i class="fas fa-check-circle me-2"></i> Safe Results ({{ safe_files }} files)</h5>
                <ul class="list-group list-group-flush" style="max-height: 400px; overflow-y: auto;">
                    {% for file in file_tree['safe'] %}
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <div class="text-truncate" style="flex-grow: 1; margin-right: 10px;">
                            <strong class="log-INFO">{{ file.name }}</strong>
                            <small class="text-white-50 d-block">({{ file.size }} | {{ file.timestamp }})</small>
                        </div>
                        <a href="{{ url_for('view_file', path=quote_plus(file.path)) }}" class="btn btn-sm btn-neon border-success text-success" style="color:var(--neon-green); border-color:var(--neon-green); box-shadow: 0 0 5px var(--neon-green);">View <i class="fas fa-check"></i></a>
                    </li>
                    {% endfor %}
                    {% if not file_tree['safe'] %}<li class="list-group-item text-warning">No safe files found. Check path.</li>{% endif %}
                </ul>
            </div>
        </div>
    </div>
</div>

<script>
    // --- Chart.js Initialization Functions ---
    
    // --- 1. PIE CHART: Log Type Distribution ---
    const pieChartData = {{ pie_chart_data | tojson | safe }};
    const pieChartCanvas = document.getElementById('logPieChart');
    const pieChartMsg = document.getElementById('pieChartMessage');

    if (pieChartData.labels.length > 0) {
        pieChartCanvas.style.display = 'block';
        new Chart(pieChartCanvas, {
            type: 'doughnut',
            data: pieChartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'right',
                        labels: { color: 'var(--text-light)', boxWidth: 15, padding: 15, font: { size: 12 } } 
                    },
                    title: { display: false }
                }
            }
        });
    } else {
        pieChartMsg.innerHTML = '<i class="fas fa-folder-open me-2"></i> No log JSON files found in {{ COLLECTED_LOGS_PATH.name }} subfolders.';
    }

    // --- 2. LINE CHART: Hourly Log Trend ---
    const lineChartData = {{ line_chart_data | tojson | safe }};
    const lineChartCanvas = document.getElementById('logLineChart');
    const lineChartMsg = document.getElementById('lineChartMessage');
    
    if (lineChartData.labels.length > 0 && lineChartData.datasets[0].data.some(v => v > 0)) {
        lineChartCanvas.style.display = 'block';
        new Chart(lineChartCanvas, {
            type: 'line',
            data: lineChartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { color: '#ffffff1a' },
                        ticks: { color: 'var(--neon-blue)', font: { size: 10 } },
                        title: { display: true, text: 'Time of Day (Hour)', color: 'var(--neon-blue)', font: { size: 12, weight: 'bold' } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: '#ffffff1a' },
                        ticks: { color: 'var(--neon-green)', font: { size: 10 } },
                        title: { display: true, text: 'Log Count', color: 'var(--neon-green)', font: { size: 12, weight: 'bold' } }
                    }
                },
                plugins: {
                    legend: { display: false },
                    title: { display: false }
                }
            }
        });
    } else {
        lineChartMsg.innerHTML = '<i class="fas fa-chart-line me-2"></i> No timestamps could be extracted from log files for trend analysis.';
    }
    
    // --- 3. BAR CHART: Browser Data Stats ---
    const barChartData = {{ bar_chart_data | tojson | safe }};
    const browserBarChartCanvas = document.getElementById('browserBarChart');
    const barChartMsg = document.getElementById('barChartMessage');

    if (barChartData.labels.length > 0 && barChartData.datasets.some(ds => ds.data.some(v => v > 0))) {
        browserBarChartCanvas.style.display = 'block';
        new Chart(browserBarChartCanvas, {
            type: 'bar',
            data: barChartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: true,
                        grid: { color: '#ffffff1a' },
                        ticks: { color: 'var(--neon-blue)', font: { size: 12, weight: 'bold' } },
                        title: { display: true, text: 'Browser', color: 'var(--neon-blue)' }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        grid: { color: '#ffffff1a' },
                        ticks: { color: 'var(--neon-green)', font: { size: 12 } },
                        title: { display: true, text: 'File Count', color: 'var(--neon-green)' }
                    }
                },
                plugins: {
                    legend: { 
                        position: 'top', 
                        labels: { color: 'var(--text-light)', boxWidth: 15, padding: 15, font: { size: 12 } } 
                    },
                    title: { display: false }
                }
            }
        });
    } else {
        barChartMsg.innerHTML = '<i class="fas fa-exclamation-circle me-2"></i> No data files found in {{ BROWSER_DIR_NAME }} to analyze.';
    }

</script>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

VIEW_TMPL = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ COMPANY_NAME }} - File View</title>
    {{ BASE_STYLES | safe }}
    <style>
        .json-key { color: var(--neon-blue); font-weight: 700; cursor: pointer; font-size: 1.05rem; }
        .json-string { color: var(--neon-yellow); font-weight: 600; }
        .json-number, .json-boolean { color: var(--neon-green); font-weight: 600; }
        .json-null { color: #808080; font-style: italic; font-weight: 400; }
        .json-object, .json-array { margin-left: 1.5rem; padding-left: 0.5rem; border-left: 2px solid #3a3a3a; }
        .json-entry { margin-bottom: 0.35rem; }
        .collapsible::before {
            content: "\f0d7"; 
            font-family: "Font Awesome 6 Free";
            font-weight: 900;
            margin-right: 0.5rem;
            transition: transform 0.2s;
        }
        .collapsible.collapsed::before {
            content: "\f0da"; 
            transform: rotate(0);
        }
        .collapsible-content { overflow: hidden; }
        pre { white-space: pre-wrap; word-wrap: break-word; font-size: 0.9rem; }
        code { color: var(--text-light); }
        .bg-dark code { color: var(--neon-green) !important; font-weight: 600;}
    </style>
</head>
<body>
<div class="container py-5">
    <h1 class="title-text border-bottom border-secondary pb-3 mb-4">
        <i class="fas fa-file-code me-2"></i> {{ filename }}
    </h1>

    <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 p-3 bg-dark rounded">
        <span class="text-white-50 mb-2 mb-md-0">Path: <code class="text-break">{{ path }}</code></span>
        <div>
            <a class="btn btn-outline-info btn-sm me-2 btn-neon" href="{{ url_for('download_file', path=quote_plus(path)) }}">
                <i class="fas fa-download me-1"></i> Download
            </a>
            <a class="btn btn-outline-secondary btn-sm btn-neon" href="{{ url_for('dashboard') }}" style="color:var(--text-light); border-color:var(--text-light); box-shadow: 0 0 5px var(--text-light);">
                <i class="fas fa-arrow-left me-1"></i> Back to Dashboard
            </a>
        </div>
    </div>
    
    <div class="card p-4">
        <h3 class="card-header mb-3"><i class="fas fa-eye me-2"></i> Interactive Data Viewer</h3>
        <div id="json-viewer-content" class="mb-4">
            {% if is_json %}
            <!-- JSON content will be rendered here by JavaScript -->
            {% else %}
            <div class="alert alert-warning text-dark">
                <i class="fas fa-info-circle me-2"></i> File content is not valid JSON or could not be parsed. Displaying raw content below.
            </div>
            {% endif %}
        </div>

        <div class="mt-5 border-top border-secondary pt-4">
            <h3 class="card-header mb-3"><i class="fas fa-terminal me-2"></i> Raw Source Content</h3>
            <pre class="bg-black text-white p-3 rounded" style="border: 1px dashed #333; overflow-x: auto;"><code>{{ pretty }}</code></pre>
        </div>
    </div>

</div>

<script>
    const jsonData = {{ obj | tojson | safe }};
    const isJson = {{ is_json | tojson | safe }};
    const viewerContainer = document.getElementById('json-viewer-content');

    if (isJson) {
        function createEntry(key, value, parentType) {
            const entry = document.createElement('div');
            entry.className = 'json-entry';

            if (typeof value === 'object' && value !== null && (Array.isArray(value) ? value.length > 0 : Object.keys(value).length > 0)) {
                const isArray = Array.isArray(value);
                
                const keyElement = document.createElement('span');
                keyElement.textContent = (parentType === 'array' ? `[${key}]` : `${key}`);
                
                const typeLabel = document.createElement('span');
                typeLabel.className = 'text-white-50 ms-2';
                typeLabel.textContent = isArray ? `[${value.length}]` : `{${Object.keys(value).length}}`;

                const collapsibleHeader = document.createElement('span');
                collapsibleHeader.className = 'json-key collapsible';
                collapsibleHeader.appendChild(keyElement);
                collapsibleHeader.appendChild(typeLabel);
                
                const isLarge = (isArray ? value.length : Object.keys(value).length) > 5;
                const initialState = isLarge ? 'collapsed' : '';

                const content = document.createElement('div');
                content.className = `collapsible-content ps-3`;
                if (initialState === 'collapsed') {
                    content.style.display = 'none';
                    collapsibleHeader.classList.add('collapsed');
                }

                collapsibleHeader.addEventListener('click', () => {
                    const isCollapsed = collapsibleHeader.classList.toggle('collapsed');
                    content.style.display = isCollapsed ? 'none' : 'block';
                });
                
                entry.appendChild(collapsibleHeader);
                entry.appendChild(content);
                renderJson(value, content, isArray ? 'array' : 'object');

            } else {
                // Primitive value or empty object/array
                const valueType = typeof value;
                let valueText;
                let valueClass;

                if (value === null) {
                    valueText = 'null';
                    valueClass = 'json-null';
                } else if (valueType === 'string') {
                    valueText = `"${value}"`;
                    valueClass = 'json-string';
                } else if (valueType === 'number' || valueType === 'boolean') {
                    valueText = String(value);
                    valueClass = 'json-number';
                } else {
                    valueText = String(value);
                    valueClass = 'text-white';
                }
                
                const keyElement = document.createElement('span');
                keyElement.className = 'json-key text-white-50 me-2';
                keyElement.textContent = (parentType === 'array' ? `[${key}]:` : `${key}:`);

                const valueElement = document.createElement('span');
                valueElement.className = valueClass;
                valueElement.textContent = valueText;

                entry.appendChild(keyElement);
                entry.appendChild(valueElement);
            }

            return entry;
        }

        function renderJson(data, container, parentType = 'object') {
            container.innerHTML = '';
            if (typeof data === 'object' && data !== null) {
                const keys = Array.isArray(data) ? [...Array(data.length).keys()] : Object.keys(data);
                keys.forEach(key => {
                    const entry = createEntry(key, data[key], parentType);
                    container.appendChild(entry);
                });
            }
        }
        
        // Start rendering the root data
        renderJson(jsonData, viewerContainer, Array.isArray(jsonData) ? 'array' : 'object');
    }
</script>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# --- Routes ---

@app.route('/')
def dashboard():
    """Main Dashboard Route - displays KPIs, Charts, and file listings."""
    
    # 1. Fetch File System Metrics
    safe_files, safe_size = get_dir_stats(safe_dir)
    alert_files, alert_size = get_dir_stats(alerts_dir)
    browser_files, browser_size = get_dir_stats(BROWSER_DIR)
    
    total_files = safe_files + alert_files + browser_files
    total_size = safe_size + alert_size + browser_size
    
    # 2. Fetch Chart Data from File Paths
    pie_chart_data = get_folder_log_stats(COLLECTED_LOGS_PATH)
    line_chart_data = get_hourly_log_trend(COLLECTED_LOGS_PATH)
    bar_chart_data = get_browser_data_stats(BROWSER_DIR)
    
    # 3. Fetch DB Data for Table
    log_data, db_status = get_db_data(DB_PATH)
    
    # 4. Fetch File Listings
    file_tree = {
        'browser': get_file_listings(BROWSER_DIR),
        'alerts': get_file_listings(alerts_dir),
        'safe': get_file_listings(safe_dir),
    }

    return render_template_string(
        DASHBOARD_TMPL,
        COMPANY_NAME=COMPANY_NAME,
        BASE_STYLES=BASE_STYLES,
        humanize=humanize, 
        COLLECTED_LOGS_PATH=COLLECTED_LOGS_PATH,
        BROWSER_DIR_NAME=BROWSER_DIR_NAME,
        
        # KPI Data
        total_files=total_files,
        total_size=total_size,
        safe_files=safe_files,
        safe_size=safe_size,
        alert_files=alert_files,
        alert_size=alert_size,
        browser_files=browser_files,
        browser_size=browser_size,
        db_status=db_status,

        # Chart Data
        pie_chart_data=pie_chart_data,
        line_chart_data=line_chart_data,
        bar_chart_data=bar_chart_data,
        
        # Table and File Listings
        log_data=log_data,
        file_tree=file_tree
    )

@app.route('/view')
def view_file():
    """View a single file content with the interactive JSON viewer."""
    path = request.args.get('path')
    if not path: abort(400)
    
    decoded_path = unquote_plus(path)
    p = Path(decoded_path)
    
    # Security check: only allow files within defined result/data directories
    if not p.exists() or not p.is_file() or not any(p.is_relative_to(d) for d in [PATHS['results_dir'], BROWSER_DIR, COLLECTED_LOGS_PATH]):
        abort(404)
        
    obj = read_json_file(p)
    is_json = obj is not None
    
    try:
        with open(p, 'r', encoding='utf-8') as f:
            pretty = f.read()
        if not is_json:
            obj = {}
    except Exception:
        pretty = "Could not read file content due to encoding or permission error."
        obj = {}
        
    return render_template_string(
        VIEW_TMPL, 
        path=str(p), 
        obj=obj, 
        pretty=pretty,
        filename=p.name,
        is_json=is_json,
        COMPANY_NAME=COMPANY_NAME,
        BASE_STYLES=BASE_STYLES
    )

@app.route('/download')
def download_file():
    """Route to download a file."""
    path = request.args.get('path')
    if not path: abort(400)
    
    decoded_path = unquote_plus(path)
    p = Path(decoded_path)
    
    if not p.exists() or not p.is_file() or not any(p.is_relative_to(d) for d in [PATHS['results_dir'], BROWSER_DIR, COLLECTED_LOGS_PATH]):
        abort(404)
        
    mime = mimetypes.guess_type(str(p))[0] or 'application/octet-stream'
    
    return send_file(str(p), as_attachment=True, download_name=p.name, mimetype=mime)


if __name__ == '__main__':
    print("Dashboard starting. Ensure your project paths are correctly set in the CONFIG section and the required folders exist.")
    app.run(debug=True)
