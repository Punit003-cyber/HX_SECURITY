

from flask import Flask, render_template_string, request, redirect, session, send_file
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
import os, sqlite3, random, csv, json, contextlib
from io import BytesIO

# ================= 1. CONFIGURATION & HARDENING =================

# Path Configuration
SPECIFIC_PATH = Path(r"C:\Users\Admin\Desktop\project")
CURRENT_PATH = Path(os.getcwd())
PROJECT_ROOT = SPECIFIC_PATH if SPECIFIC_PATH.exists() else CURRENT_PATH


DIRS = {
    "alerts": PROJECT_ROOT / "results/alerts",
    "safe": PROJECT_ROOT / "results/safe",
    "browser": PROJECT_ROOT / "Browser_Extraction",
    "logs": PROJECT_ROOT / "collected_logs",
    "uploads": PROJECT_ROOT / "uploads"
}

# Database Paths
DB_FILES = {
    "Platform": PROJECT_ROOT / "soc_platform.db",
    "Scanner": PROJECT_ROOT / "scanner_meta.db",
    "Dashboard": PROJECT_ROOT / "soc_dashboard.db"
}

IOC_FILE = PROJECT_ROOT / "iocs.csv"
MAIN_DB_PATH = DB_FILES["Platform"]
APP_SECRET = "hx-enterprise-secret-key-999-prod"
COMPANY = "HX SECURITY"

# Initialize App
app = Flask(__name__)
app.secret_key = APP_SECRET

# Ensure Environment
for d in DIRS.values():
    d.mkdir(parents=True, exist_ok=True)

if not IOC_FILE.exists():
    with open(IOC_FILE, 'w', newline='') as f:
        csv.writer(f).writerow(["type", "value", "description"])

# Auth Configuration
USERS = {
    "analyst": {"password": "hx123", "role": "SOC_ANALYST"},
    "admin": {"password": "hxadmin", "role": "SOC_ADMIN"}
}

# ================= 2. DATABASE ENGINE (OPTIMIZED) =================

def get_db_connection(db_path=MAIN_DB_PATH):
    """Production-ready DB connection factory."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row # Access columns by name
        return conn
    except Exception as e:
        print(f"[ERROR] DB Connection failed: {e}")
        return None

def init_main_db():
    """Initializes schema if missing."""
    with contextlib.closing(get_db_connection()) as conn:
        if not conn: return
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                severity TEXT,
                source TEXT,
                description TEXT,
                mitre TEXT DEFAULT 'T0000',
                kill_chain TEXT DEFAULT 'Reconnaissance'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit (
                timestamp TEXT,
                user TEXT,
                action TEXT
            )
        """)
        conn.commit()

init_main_db()

# ================= 3. LOGIC, HELPERS & ANALYTICS =================

def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def audit(action):
    """Log user actions silently."""
    try:
        with contextlib.closing(get_db_connection()) as conn:
            conn.execute("INSERT INTO audit VALUES (?,?,?)", 
                        (now(), session.get("user", "system"), action))
            conn.commit()
    except: pass

def get_analytics_data():
    """
    Complex data aggregation for the 4 charts.
    Returns structured JSON-ready dictionaries.
    """
    with contextlib.closing(get_db_connection()) as conn:
        if not conn: return {}, {}, {}, {}
        
        # Fetch all alerts
        rows = conn.execute("SELECT timestamp, severity, source, mitre FROM alerts ORDER BY timestamp ASC").fetchall()

    # 1. Line Chart: Volume Over Time (Group by Date)
    dates = [r["timestamp"].split(" ")[0] for r in rows if r["timestamp"]]
    date_counts = Counter(dates)
    sorted_dates = sorted(date_counts.keys())
    line_data = {
        "labels": sorted_dates,
        "values": [date_counts[d] for d in sorted_dates]
    }

    # 2. Pie Chart: Severity
    sevs = [r["severity"] for r in rows]
    sev_counts = Counter(sevs)
    pie_sev_data = {
        "labels": list(sev_counts.keys()),
        "values": list(sev_counts.values())
    }

    # 3. Pie Chart: LOG SOURCE DETECTION (REAL DATA FROM DISK)
    # This logic scans the specific folders and counts files
    target_folders = [
        "application_logs", "dns_logs", "edr_logs", "file_logs", 
        "firewall_logs", "network_logs", "process_logs", "registry_logs",
        "scheduled_tasks_logs", "security_logs", "software_logs", "system_logs",
        "third_party_logs", "usb_logs", "user_logs"
    ]
    
    real_labels = []
    real_counts = []
    
    for folder_name in target_folders:
        # Construct path: .../project/collected_logs/folder_name
        folder_path = DIRS["logs"] / folder_name
        
        # Create a pretty label (e.g. "application_logs" -> "Application Logs")
        clean_label = folder_name.replace("_", " ").title()
        real_labels.append(clean_label)
        
        count = 0
        if folder_path.exists():
            # Count only files (ignore nested folders if any)
            try:
                count = sum(1 for _ in folder_path.iterdir() if _.is_file())
            except Exception as e:
                print(f"Error reading {folder_name}: {e}")
        real_counts.append(count)

    pie_src_data = {
        "labels": real_labels,
        "values": real_counts
    }

    # 4. Bar Chart: Top 5 MITRE Techniques
    mitres = [r["mitre"] for r in rows if r["mitre"] != "T0000"]
    mitre_counts = Counter(mitres).most_common(5)
    bar_mitre_data = {
        "labels": [m[0] for m in mitre_counts],
        "values": [m[1] for m in mitre_counts]
    }

    return line_data, pie_sev_data, pie_src_data, bar_mitre_data

def generate_demo_alerts():
    """Generates enhanced dummy data with history for the Line Graph."""
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sources = ["Firewall", "EDR", "ActiveDirectory", "WebGateway"]
    mitre_map = {
        "T1059": "Execution", "T1190": "Initial Access", 
        "T1078": "Defense Evasion", "T1003": "Credential Access"
    }
    
    with contextlib.closing(get_db_connection()) as conn:
        for i in range(15):
            # Backdate some entries to create a trend line
            days_ago = random.randint(0, 6)
            fake_date = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")
            
            mitre_id = random.choice(list(mitre_map.keys()))
            conn.execute(
                "INSERT INTO alerts VALUES (NULL,?,?,?,?,?,?)",
                (fake_date, 
                 random.choice(severities),
                 random.choice(sources),
                 f"Simulated Threat Simulation #{i}",
                 mitre_id,
                 mitre_map[mitre_id]) 
            )
        conn.commit()

# ================= 4. MODERN FRONTEND (CSS/JS) =================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} | HX Security</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        /* --- CYBER DARK THEME --- */
        :root {
            --bg-body: #0f172a;
            --bg-card: #1e293b;
            --bg-sidebar: #020617;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;         /* Light Blue */
            --accent-glow: rgba(56, 189, 248, 0.15);
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --border: #334155;
        }

        body {
            background-color: var(--bg-body);
            color: var(--text-primary);
            font-family: 'Segoe UI', system-ui, sans-serif;
            overflow-x: hidden;
        }

        /* Typography */
        h1, h2, h3, h4, h5, h6 { color: var(--text-primary); font-weight: 600; }
        .text-muted { color: var(--text-secondary) !important; }
        .text-accent { color: var(--accent) !important; }

        /* Sidebar Navigation */
        .sidebar {
            width: 250px;
            position: fixed;
            top: 0; bottom: 0; left: 0;
            background: var(--bg-sidebar);
            border-right: 1px solid var(--border);
            padding: 20px 15px;
            z-index: 1000;
            display: flex;
            flex-direction: column;
        }
        .brand-logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            text-align: center;
            margin-bottom: 2rem;
            letter-spacing: 1px;
            text-shadow: 0 0 10px rgba(56, 189, 248, 0.5);
        }
        .nav-link {
            color: var(--text-secondary);
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 5px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        .nav-link:hover, .nav-link.active {
            background: var(--accent-glow);
            color: var(--accent);
            transform: translateX(5px);
        }
        .nav-link i { width: 25px; }

        /* Main Content */
        .content {
            margin-left: 250px;
            padding: 30px;
            min-height: 100vh;
        }

        /* Cards & Glassmorphism */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            margin-bottom: 24px;
        }
        .card-header {
            background: rgba(30, 41, 59, 0.5);
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
            font-weight: 600;
            padding: 15px 20px;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
        }
        
        /* Tables */
        .table {
            --bs-table-bg: transparent;
            --bs-table-color: var(--text-primary);
            border-color: var(--border);
        }
        .table thead th {
            color: var(--accent);
            font-size: 0.85rem;
            text-transform: uppercase;
            border-bottom: 2px solid var(--border);
        }
        .table-hover tbody tr:hover td {
            color: #fff;
            background-color: rgba(56, 189, 248, 0.05);
        }

        /* Form Elements */
        .form-control, .form-select {
            background-color: #020617;
            border: 1px solid var(--border);
            color: #fff;
        }
        .form-control:focus {
            background-color: #020617;
            border-color: var(--accent);
            color: #fff;
            box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.25);
        }

        /* Custom Badges */
        .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
        .badge-HIGH { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }
        .badge-MEDIUM { background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid #3b82f6; }
        .badge-LOW { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }

        /* Charts */
        canvas { max-height: 300px; width: 100%; }

        /* Login Page Override & Animations */
        .login-wrapper {
            background: radial-gradient(circle at center, #1e293b 0%, #020617 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(40px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes float {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
            100% { transform: translateY(0px); }
        }
        
        .login-anim-enter {
            animation: fadeInUp 0.8s ease-out forwards;
        }
        .logo-float {
            animation: float 4s ease-in-out infinite;
        }
    </style>
</head>
<body>

{% if not hide_sidebar %}
<div class="sidebar">
    <div class="brand-logo"><i class="fas fa-shield-virus text-accent"></i> HX SECURITY</div>
    
    <nav class="nav flex-column">
        <a href="/overview" class="nav-link"><i class="fas fa-chart-line"></i> Dashboard</a>
        <a href="/alerts" class="nav-link"><i class="fas fa-bell"></i> Alerts & Mitre</a>
        <a href="/databases" class="nav-link"><i class="fas fa-database"></i> DB Viewer</a>
        <a href="/iocs" class="nav-link"><i class="fas fa-fingerprint"></i> IOC Manager</a>
        <a href="/files" class="nav-link"><i class="fas fa-folder-open"></i> File Artifacts</a>
        <a href="/audit" class="nav-link"><i class="fas fa-history"></i> Audit Logs</a>
    </nav>

    <div class="mt-auto">
        <hr style="border-color: var(--border)">
        <a href="/report" class="nav-link text-warning"><i class="fas fa-file-download"></i> Reports</a>
        {% if role == 'SOC_ADMIN' %}
        <a href="/generate-demo" class="nav-link text-success"><i class="fas fa-magic"></i> Demo Data</a>
        {% endif %}
        <a href="/logout" class="nav-link text-danger mt-2"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </div>
</div>
{% endif %}

<div class="{% if not hide_sidebar %}content{% endif %}">
    {{ content|safe }}
</div>

<script>
    // Active Link Highlighter
    const currentPath = window.location.pathname;
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        if(link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
</script>
</body>
</html>
"""

# ================= 5. ROUTE HANDLERS =================

@app.route("/", methods=["GET", "POST"])
def login():
    if "user" in session: return redirect("/overview")
    error = ""
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        if u in USERS and USERS[u]["password"] == p:
            session["user"] = u
            session["role"] = USERS[u]["role"]
            audit(f"User {u} logged in")
            return redirect("/overview")
        error = "Access Denied: Invalid Credentials"

    html = f"""
    <div class="login-wrapper">
        <div class="card p-5 login-anim-enter" style="width: 400px; border-top: 4px solid var(--accent);">
            <div class="text-center mb-4">
                <h1 class="text-white display-6 fw-bold logo-float">HX <span class="text-accent">SOC</span></h1>
                <p class="text-muted">Enterprise Threat Intelligence</p>
            </div>
            {f'<div class="alert alert-danger py-2">{error}</div>' if error else ''}
            <form method="post">
                <div class="mb-3">
                    <label class="text-secondary small">Username</label>
                    <input class="form-control" name="username" required autocomplete="off">
                </div>
                <div class="mb-4">
                    <label class="text-secondary small">Password</label>
                    <input class="form-control" type="password" name="password" required>
                </div>
                <button class="btn btn-primary w-100 py-2 fw-bold" style="background:var(--accent); border:none; color:black">AUTHENTICATE</button>
            </form>
        </div>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Login", hide_sidebar=True, content=html)

@app.route("/logout")
def logout():
    audit("User logged out")
    session.clear()
    return redirect("/")

@app.route("/overview")
def overview():
    if "user" not in session: return redirect("/")
    
    # 1. Get File Stats
    n_alerts = sum(1 for _ in DIRS['alerts'].rglob("*") if _.is_file())
    n_safe = sum(1 for _ in DIRS['safe'].rglob("*") if _.is_file())
    
    # 2. Get Chart Data
    line_d, pie_sev_d, pie_src_d, bar_mitre_d = get_analytics_data()

    html = f"""
    <div class="d-flex justify-content-between align-items-center mb-5">
        <div>
            <h2 class="mb-1">Security Operations Center</h2>
            <p class="text-muted mb-0">Real-time threat monitoring and artifact analysis.</p>
        </div>
        <div class="text-end">
            <span class="badge bg-success px-3 py-2 me-2">SYSTEM ONLINE</span>
            <span class="text-muted small">{now()}</span>
        </div>
    </div>

    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card p-3 border-danger h-100 d-flex flex-row align-items-center">
                <div class="display-5 text-danger me-3"><i class="fas fa-bug"></i></div>
                <div>
                    <h3 class="mb-0">{n_alerts}</h3>
                    <small class="text-muted">Active Threats</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card p-3 border-success h-100 d-flex flex-row align-items-center">
                <div class="display-5 text-success me-3"><i class="fas fa-check-circle"></i></div>
                <div>
                    <h3 class="mb-0">{n_safe}</h3>
                    <small class="text-muted">Safe Files</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card p-3 border-primary h-100 d-flex flex-row align-items-center">
                <div class="display-5 text-primary me-3"><i class="fas fa-network-wired"></i></div>
                <div>
                    <h3 class="mb-0">{sum(bar_mitre_d['values'])}</h3>
                    <small class="text-muted">MITRE Events</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card p-3 border-warning h-100 d-flex flex-row align-items-center">
                <div class="display-5 text-warning me-3"><i class="fas fa-user-shield"></i></div>
                <div>
                    <h3 class="mb-0">{session['user'].upper()}</h3>
                    <small class="text-muted">Active Analyst</small>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-8">
            <div class="card h-100">
                <div class="card-header"><i class="fas fa-wave-square me-2"></i> Alert Volume Trend (Timeline)</div>
                <div class="card-body">
                    <canvas id="lineChart"></canvas>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card h-100">
                <div class="card-header"><i class="fas fa-chart-pie me-2"></i> Severity Distribution</div>
                <div class="card-body">
                    <canvas id="pieSevChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <div class="row mt-4">
        <div class="col-md-6">
            <div class="card h-100">
                <div class="card-header"><i class="fas fa-bars me-2"></i> Top 5 MITRE Techniques</div>
                <div class="card-body">
                    <canvas id="barChart"></canvas>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card h-100">
                <div class="card-header"><i class="fas fa-bullseye me-2"></i> Log Source Detection</div>
                <div class="card-body">
                    <canvas id="pieSrcChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <script>
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = '#334155';

    // 1. Line Chart Config
    new Chart(document.getElementById('lineChart'), {{
        type: 'line',
        data: {{
            labels: {json.dumps(line_d['labels'])},
            datasets: [{{
                label: 'Alerts Detected',
                data: {json.dumps(line_d['values'])},
                borderColor: '#38bdf8',
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                tension: 0.4,
                fill: true
            }}]
        }},
        options: {{ maintainAspectRatio: false }}
    }});

    // 2. Pie Severity Config
    new Chart(document.getElementById('pieSevChart'), {{
        type: 'doughnut',
        data: {{
            labels: {json.dumps(pie_sev_d['labels'])},
            datasets: [{{
                data: {json.dumps(pie_sev_d['values'])},
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
                borderWidth: 0
            }}]
        }}
    }});

    // 3. Bar MITRE Config
    new Chart(document.getElementById('barChart'), {{
        type: 'bar',
        data: {{
            labels: {json.dumps(bar_mitre_d['labels'])},
            datasets: [{{
                label: 'Occurrences',
                data: {json.dumps(bar_mitre_d['values'])},
                backgroundColor: '#8b5cf6',
                borderRadius: 5
            }}]
        }},
        options: {{ 
            indexAxis: 'y',
            maintainAspectRatio: false
        }}
    }});

    // 4. Pie Source Config (UPDATED FOR REAL DATA)
    new Chart(document.getElementById('pieSrcChart'), {{
        type: 'pie',
        data: {{
            labels: {json.dumps(pie_src_d['labels'])},
            datasets: [{{
                data: {json.dumps(pie_src_d['values'])},
                backgroundColor: [
                    '#38bdf8', '#ef4444', '#22c55e', '#f59e0b', '#a855f7', 
                    '#ec4899', '#6366f1', '#14b8a6', '#f97316', '#84cc16', 
                    '#06b6d4', '#d946ef', '#e11d48', '#8b5cf6', '#64748b'
                ], 
                borderWidth: 0
            }}]
        }}
    }});
    </script>
    """
    return render_template_string(BASE_TEMPLATE, title="Dashboard", content=html, role=session.get("role"))

@app.route("/alerts")
def alerts_page():
    if "user" not in session: return redirect("/")
    
    sev_filter = request.args.get("severity")
    query = "SELECT * FROM alerts ORDER BY id DESC"
    params = ()
    if sev_filter:
        query = "SELECT * FROM alerts WHERE severity=? ORDER BY id DESC"
        params = (sev_filter,)

    with contextlib.closing(get_db_connection()) as conn:
        rows = conn.execute(query, params).fetchall()

    table_rows = ""
    for r in rows:
        table_rows += f"""
        <tr>
            <td>{r['timestamp']}</td>
            <td><span class='badge badge-{r['severity']}'>{r['severity']}</span></td>
            <td>{r['source']}</td>
            <td>{r['description']}</td>
            <td class="text-accent fw-bold">{r['mitre']}</td>
            <td><small class="text-muted">{r['kill_chain']}</small></td>
        </tr>
        """

    html = f"""
    <div class="d-flex justify-content-between mb-4">
        <h2>Threat Alerts</h2>
        <div class="btn-group">
            <a href="/alerts" class="btn btn-outline-secondary">All</a>
            <a href="/alerts?severity=CRITICAL" class="btn btn-outline-danger">Critical</a>
            <a href="/alerts?severity=HIGH" class="btn btn-outline-warning">High</a>
            <a href="/alerts?severity=LOW" class="btn btn-outline-info">Low</a>
        </div>
    </div>
    
    <div class="card">
        <div class="table-responsive">
            <table class="table table-hover mb-0 align-middle">
                <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Description</th><th>MITRE ID</th><th>Kill Chain</th></tr></thead>
                <tbody>{table_rows}</tbody>
            </table>
        </div>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Alerts", content=html, role=session.get("role"))

@app.route("/databases")
def databases():
    if "user" not in session: return redirect("/")
    
    current_db = request.args.get("db", "Platform")
    current_table = request.args.get("table", "")
    
    # Get Tables
    tables = []
    path = DB_FILES.get(current_db)
    if path and path.exists():
        with contextlib.closing(get_db_connection(path)) as conn:
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
    
    # Get Data
    cols, data_rows = [], []
    if current_table and path:
        with contextlib.closing(get_db_connection(path)) as conn:
            try:
                cur = conn.execute(f"SELECT * FROM {current_table} ORDER BY rowid DESC LIMIT 100")
                data_rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
            except Exception as e:
                print(e)

    # UI Construction
    db_nav = "".join([f'<a href="?db={k}" class="btn btn-sm me-2 { "btn-primary" if k==current_db else "btn-outline-secondary" }">{k}</a>' for k in DB_FILES.keys()])
    
    table_nav = ""
    for t in tables:
        active = "text-accent bg-dark" if t == current_table else "text-muted"
        table_nav += f'<a href="?db={current_db}&table={t}" class="list-group-item list-group-item-action {active}" style="background-color:transparent; border-color:var(--border)">{t}</a>'
    
    table_html = ""
    if data_rows:
        thead = "".join([f"<th>{c}</th>" for c in cols])
        tbody = "".join([f"<tr>{''.join([f'<td><div class=text-truncate style=max-width:150px>{x}</div></td>' for x in row])}</tr>" for row in data_rows])
        table_html = f"<table class='table table-sm table-striped'><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>"
    else:
        table_html = "<div class='p-5 text-center text-muted'>Select a table to inspect schema and data.</div>"

    html = f"""
    <h2>Database Inspector</h2>
    <div class="mb-4">{db_nav}</div>
    <div class="row">
        <div class="col-md-3">
            <div class="card">
                <div class="card-header">Tables in {current_db}</div>
                <div class="list-group list-group-flush">{table_nav}</div>
            </div>
        </div>
        <div class="col-md-9">
            <div class="card">
                <div class="card-header">Data View: {current_table or 'None'}</div>
                <div class="card-body p-0 table-responsive">{table_html}</div>
            </div>
        </div>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Databases", content=html, role=session.get("role"))

@app.route("/iocs", methods=["GET", "POST"])
def iocs():
    if "user" not in session: return redirect("/")
    
    if request.method == "POST":
        new_content = request.form.get("content")
        with open(IOC_FILE, "w") as f: f.write(new_content)
        audit("Updated IOC Definition File")
        return redirect("/iocs")
    
    content = ""
    if IOC_FILE.exists():
        with open(IOC_FILE, "r") as f: content = f.read()

    html = f"""
    <h2>IOC Management</h2>
    <div class="card">
        <div class="card-header d-flex justify-content-between">
            <span>Edit iocs.csv</span>
            <span class="badge bg-warning text-dark">Production Config</span>
        </div>
        <div class="card-body">
            <form method="post">
                <textarea name="content" class="form-control mb-3" rows="20" 
                    style="font-family: 'JetBrains Mono', monospace; background: #0b1220; color: #a5d8ff; border-color: var(--border);">{content}</textarea>
                <button class="btn btn-success fw-bold"><i class="fas fa-save me-2"></i> Deploy Changes</button>
            </form>
        </div>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="IOCs", content=html, role=session.get("role"))

@app.route("/files")
def files():
    if "user" not in session: return redirect("/")
    
    file_rows = ""
    for cat, path in DIRS.items():
        if path.exists():
            for f in path.rglob("*"):
                if f.is_file():
                    icon = "fa-file-code" if f.suffix == ".json" else "fa-file"
                    file_rows += f"""
                    <tr>
                        <td><span class="badge bg-secondary">{cat.upper()}</span></td>
                        <td><i class="fas {icon} me-2 text-muted"></i>{f.name}</td>
                        <td class="text-muted">{f.stat().st_size} B</td>
                        <td class="text-end text-muted">{datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M')}</td>
                    </tr>"""
    
    html = f"""
    <h2>Artifact Repository</h2>
    <div class="card">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead><tr><th>Category</th><th>Filename</th><th>Size</th><th class="text-end">Modified</th></tr></thead>
                <tbody>{file_rows}</tbody>
            </table>
        </div>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Files", content=html, role=session.get("role"))

@app.route("/audit")
def audit_log():
    if "user" not in session: return redirect("/")
    
    with contextlib.closing(get_db_connection()) as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY timestamp DESC LIMIT 100").fetchall()
    
    html = f"""
    <h2>System Audit Trail</h2>
    <div class="card">
        <table class="table table-sm table-hover mb-0">
            <thead><tr><th>Timestamp</th><th>User Identity</th><th>Action Performed</th></tr></thead>
            <tbody>
                {''.join([f"<tr><td class='text-muted'>{r['timestamp']}</td><td class='text-accent'>{r['user']}</td><td>{r['action']}</td></tr>" for r in rows])}
            </tbody>
        </table>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, title="Audit", content=html, role=session.get("role"))

@app.route("/generate-demo")
def demo():
    if session.get("role") != "SOC_ADMIN": return redirect("/")
    generate_demo_alerts()
    audit("Admin triggered demo data generation")
    return redirect("/overview")

@app.route("/report")
def report():
    if "user" not in session: return redirect("/")
    # Build a simple text report
    lines = [f"HX SECURITY REPORT - {now()}", "="*40, ""]
    with contextlib.closing(get_db_connection()) as conn:
        alerts = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
        for a in alerts:
            lines.append(f"[{a['timestamp']}] {a['severity']} | {a['source']}")
            lines.append(f"Desc: {a['description']}")
            lines.append(f"MITRE: {a['mitre']} ({a['kill_chain']})")
            lines.append("-" * 20)
            
    return send_file(
        BytesIO("\n".join(lines).encode('utf-8')),
        download_name=f"SOC_Report_{datetime.now().strftime('%Y%m%d')}.txt",
        as_attachment=True,
        mimetype="text/plain"
    )

if __name__ == "__main__":
    app.run(debug=True, port=5000)
