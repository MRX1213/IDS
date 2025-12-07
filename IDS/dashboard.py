"""
Web Dashboard for IDS
Provides real-time visualization of alerts and statistics
"""
from flask import Flask, render_template_string, jsonify, request
from datetime import datetime
import json
from typing import Optional
from ids_core import IDSCore


# HTML Template for Dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .status-bar {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 15px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            min-width: 150px;
        }
        .stat-card h3 {
            font-size: 12px;
            opacity: 0.9;
            margin-bottom: 5px;
        }
        .stat-card .value {
            font-size: 24px;
            font-weight: bold;
        }
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        @media (max-width: 968px) {
            .main-content { grid-template-columns: 1fr; }
        }
        .panel {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .panel h2 {
            color: #667eea;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        .alert-item {
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 6px;
            border-left: 4px solid #ccc;
            background: #f9f9f9;
        }
        .alert-item.high {
            border-left-color: #e74c3c;
            background: #fee;
        }
        .alert-item.medium {
            border-left-color: #f39c12;
            background: #fff4e6;
        }
        .alert-item.low {
            border-left-color: #3498db;
            background: #e6f3ff;
        }
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        .alert-type {
            font-weight: bold;
            color: #333;
        }
        .alert-severity {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-high { background: #e74c3c; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #3498db; color: white; }
        .alert-details {
            font-size: 13px;
            color: #666;
            margin-top: 5px;
        }
        .alert-time {
            font-size: 11px;
            color: #999;
            margin-top: 5px;
        }
        .chart-container {
            height: 300px;
            margin-top: 15px;
        }
        .controls {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        button {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover { background: #5568d3; }
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        .btn-danger:hover { background: #c0392b; }
        .btn-success {
            background: #27ae60;
            color: white;
        }
        .btn-success:hover { background: #229954; }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-running { background: #27ae60; }
        .status-stopped { background: #e74c3c; }
        .refresh-info {
            text-align: right;
            font-size: 12px;
            color: #999;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Intrusion Detection System Dashboard</h1>
            <div class="status-bar">
                <div class="stat-card">
                    <h3>Status</h3>
                    <div class="value" id="status">Loading...</div>
                </div>
                <div class="stat-card">
                    <h3>Packets Processed</h3>
                    <div class="value" id="packets">0</div>
                </div>
                <div class="stat-card">
                    <h3>Total Alerts</h3>
                    <div class="value" id="total-alerts">0</div>
                </div>
                <div class="stat-card">
                    <h3>High Severity</h3>
                    <div class="value" id="high-alerts">0</div>
                </div>
                <div class="stat-card">
                    <h3>Uptime</h3>
                    <div class="value" id="uptime">0s</div>
                </div>
            </div>
            <div class="controls" style="margin-top: 15px;">
                <button class="btn-primary" onclick="refreshData()">🔄 Refresh</button>
                <button class="btn-success" onclick="startIDS()" id="start-btn">▶️ Start IDS</button>
                <button class="btn-danger" onclick="stopIDS()" id="stop-btn">⏹️ Stop IDS</button>
            </div>
        </div>
        
        <div class="main-content">
            <div class="panel">
                <h2>Recent Alerts</h2>
                <div id="alerts-container">
                    <p style="color: #999; text-align: center; padding: 20px;">No alerts yet...</p>
                </div>
            </div>
            
            <div class="panel">
                <h2>Statistics</h2>
                <div id="stats-container">
                    <p style="color: #999; text-align: center; padding: 20px;">Loading statistics...</p>
                </div>
            </div>
        </div>
        
        <div class="refresh-info">
            Auto-refreshing every <span id="refresh-interval">2</span> seconds
        </div>
    </div>
    
    <script>
        let refreshInterval;
        
        function formatTime(seconds) {
            if (seconds < 60) return Math.floor(seconds) + 's';
            if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + Math.floor(seconds % 60) + 's';
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            return hours + 'h ' + minutes + 'm';
        }
        
        function formatTimestamp(timestamp) {
            if (!timestamp) return 'Unknown';
            const date = new Date(timestamp);
            return date.toLocaleString();
        }
        
        function getSeverityClass(severity) {
            return severity ? severity.toLowerCase() : 'low';
        }
        
        function refreshData() {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    // Update status
                    const status = data.running ? 'Running' : 'Stopped';
                    document.getElementById('status').innerHTML = 
                        `<span class="status-indicator status-${data.running ? 'running' : 'stopped'}"></span>${status}`;
                    
                    // Update stats
                    const stats = data.stats || {};
                    document.getElementById('packets').textContent = stats.packets_processed || 0;
                    document.getElementById('total-alerts').textContent = stats.alerts_generated || 0;
                    document.getElementById('uptime').textContent = formatTime(stats.uptime_seconds || 0);
                    
                    // Update detection stats
                    const detStats = data.detection_stats || {};
                    const severityCounts = detStats.alerts_by_severity || {};
                    document.getElementById('high-alerts').textContent = severityCounts.HIGH || 0;
                    
                    // Update alerts
                    fetch('/api/alerts?limit=20')
                        .then(r => r.json())
                        .then(alerts => {
                            const container = document.getElementById('alerts-container');
                            if (alerts.length === 0) {
                                container.innerHTML = '<p style="color: #999; text-align: center; padding: 20px;">No alerts yet...</p>';
                            } else {
                                container.innerHTML = alerts.map(alert => `
                                    <div class="alert-item ${getSeverityClass(alert.severity)}">
                                        <div class="alert-header">
                                            <span class="alert-type">${alert.type || 'UNKNOWN'}</span>
                                            <span class="alert-severity severity-${getSeverityClass(alert.severity)}">
                                                ${alert.severity || 'LOW'}
                                            </span>
                                        </div>
                                        <div class="alert-details">${alert.description || 'No description'}</div>
                                        <div class="alert-time">${formatTimestamp(alert.timestamp || alert.detected_at)}</div>
                                    </div>
                                `).join('');
                            }
                        });
                    
                    // Update statistics panel
                    const statsContainer = document.getElementById('stats-container');
                    const typeCounts = detStats.alerts_by_type || {};
                    const typeHtml = Object.entries(typeCounts).map(([type, count]) => 
                        `<div style="padding: 8px; border-bottom: 1px solid #eee;">
                            <strong>${type}:</strong> ${count}
                        </div>`
                    ).join('');
                    statsContainer.innerHTML = typeHtml || '<p style="color: #999;">No statistics available</p>';
                })
                .catch(err => {
                    console.error('Error fetching data:', err);
                });
        }
        
        function startIDS() {
            fetch('/api/start', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    alert(data.message || 'IDS started');
                    refreshData();
                })
                .catch(err => {
                    alert('Error starting IDS: ' + err);
                });
        }
        
        function stopIDS() {
            fetch('/api/stop', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    alert(data.message || 'IDS stopped');
                    refreshData();
                })
                .catch(err => {
                    alert('Error stopping IDS: ' + err);
                });
        }
        
        // Auto-refresh
        function startAutoRefresh(interval) {
            if (refreshInterval) clearInterval(refreshInterval);
            refreshInterval = setInterval(refreshData, interval * 1000);
            document.getElementById('refresh-interval').textContent = interval;
        }
        
        // Initial load
        refreshData();
        startAutoRefresh(2);
    </script>
</body>
</html>
"""


class IDSDashboard:
    """Web Dashboard for IDS"""
    
    def __init__(self, ids_core: IDSCore, host: str = "127.0.0.1", port: int = 5000):
        self.ids_core = ids_core
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            return render_template_string(DASHBOARD_HTML)
        
        @self.app.route('/api/status')
        def api_status():
            return jsonify(self.ids_core.get_status())
        
        @self.app.route('/api/alerts')
        def api_alerts():
            limit = request.args.get('limit', 50, type=int)
            alerts = self.ids_core.get_recent_alerts(limit)
            return jsonify(alerts)
        
        @self.app.route('/api/alerts/<alert_type>')
        def api_alerts_by_type(alert_type):
            alerts = self.ids_core.get_alerts_by_type(alert_type)
            return jsonify(alerts)
        
        @self.app.route('/api/start', methods=['POST'])
        def api_start():
            try:
                self.ids_core.start()
                return jsonify({"message": "IDS started successfully", "status": "running"})
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/stop', methods=['POST'])
        def api_stop():
            try:
                self.ids_core.stop()
                return jsonify({"message": "IDS stopped successfully", "status": "stopped"})
            except Exception as e:
                return jsonify({"error": str(e)}), 500
    
    def run(self, debug: bool = False):
        """Run the dashboard server"""
        print(f"Starting IDS Dashboard on http://{self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=debug, use_reloader=False)

