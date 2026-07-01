from flask import Flask, render_template_string, jsonify, request
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from threading import Thread
import time
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)

# Global packet storage
packets = []
stats = {
    'total_packets': 0,
    'tcp_count': 0,
    'udp_count': 0,
    'icmp_count': 0,
    'dns_count': 0,
    'other_count': 0,
    'src_ips': defaultdict(int),
    'dst_ips': defaultdict(int),
    'protocols': defaultdict(int),
    'packet_sizes': [],
    'start_time': time.time()
}

MAX_PACKETS = 500

def packet_callback(packet):
    global packets, stats
    
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            size = len(packet)
            
            packet_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': 'Unknown',
                'size': size,
                'details': ''
            }
            
            # Determine protocol
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['details'] = f"Port: {packet[TCP].dport}"
                stats['tcp_count'] += 1
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['details'] = f"Port: {packet[UDP].dport}"
                stats['udp_count'] += 1
                
                # Check for DNS
                if DNS in packet:
                    packet_info['protocol'] = 'DNS'
                    stats['dns_count'] += 1
                    if DNSQR in packet:
                        packet_info['details'] = f"Query: {packet[DNSQR].qname.decode('utf-8', errors='ignore')}"
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                stats['icmp_count'] += 1
            else:
                stats['other_count'] += 1
            
            # Update stats
            stats['total_packets'] += 1
            stats['src_ips'][src_ip] += 1
            stats['dst_ips'][dst_ip] += 1
            stats['protocols'][packet_info['protocol']] += 1
            stats['packet_sizes'].append(size)
            
            # Keep only last 500 packets
            packets.append(packet_info)
            if len(packets) > MAX_PACKETS:
                packets.pop(0)
    
    except Exception as e:
        pass

# Start packet sniffing in background
def start_sniffer():
    try:
        sniff(prn=packet_callback, store=False, iface=None)
    except:
        pass

# Start sniffer thread
sniffer_thread = Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analyzer</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
* {margin: 0; padding: 0; box-sizing: border-box;}
body {font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px;}
.container {max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); padding: 40px;}
header {text-align: center; margin-bottom: 40px;}
header h1 {font-size: 2.5em; color: #2c3e50; margin-bottom: 10px;}
header p {font-size: 1.1em; color: #7f8c8d;}
.metrics {display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px;}
.metric-card {background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center;}
.metric-label {font-size: 0.9em; opacity: 0.9; margin-bottom: 8px;}
.metric-value {font-size: 2em; font-weight: 700;}
.charts {display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 30px;}
.chart-box {background: #f8f9fa; padding: 20px; border-radius: 8px;}
.chart-box h3 {color: #2c3e50; margin-bottom: 15px;}
.packets-table {width: 100%; border-collapse: collapse; background: white; margin-top: 20px;}
.packets-table th {background: #667eea; color: white; padding: 12px; text-align: left; font-weight: 600;}
.packets-table td {padding: 10px 12px; border-bottom: 1px solid #ecf0f1;}
.packets-table tr:hover {background: #f8f9fa;}
.status {padding: 15px; background: #d4edda; color: #155724; border-radius: 8px; margin-bottom: 20px;}
.error {padding: 15px; background: #f8d7da; color: #721c24; border-radius: 8px; margin-bottom: 20px;}
@media (max-width: 768px) {.container {padding: 20px;} .charts {grid-template-columns: 1fr;}}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Network Traffic Analyzer</h1>
            <p>Real-time packet capture and protocol analysis</p>
        </header>

        <div class="status">
             <strong>Live:</strong> Capturing network packets in real-time. Updating every 2 seconds.
        </div>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-label">Total Packets</div>
                <div class="metric-value" id="totalPackets">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">TCP</div>
                <div class="metric-value" id="tcpCount">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">UDP</div>
                <div class="metric-value" id="udpCount">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">DNS</div>
                <div class="metric-value" id="dnsCount">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">ICMP</div>
                <div class="metric-value" id="icmpCount">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Avg Packet Size</div>
                <div class="metric-value" id="avgSize">0 B</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-box">
                <h3>Protocol Distribution</h3>
                <canvas id="protocolChart"></canvas>
            </div>
            <div class="chart-box">
                <h3>Packet Size Distribution</h3>
                <canvas id="sizeChart"></canvas>
            </div>
            <div class="chart-box">
                <h3>Top Source IPs</h3>
                <canvas id="srcChart"></canvas>
            </div>
            <div class="chart-box">
                <h3>Top Destination IPs</h3>
                <canvas id="dstChart"></canvas>
            </div>
        </div>

        <h3 style="color: #2c3e50; margin-top: 40px; margin-bottom: 20px;">📋 Latest Packets</h3>
        <table class="packets-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>Dest IP</th>
                    <th>Protocol</th>
                    <th>Size (bytes)</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody id="packetBody">
            </tbody>
        </table>
    </div>

    <script>
        let protocolChart = null;
        let sizeChart = null;
        let srcChart = null;
        let dstChart = null;

        async function updateData() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();

                // Update metrics
                document.getElementById('totalPackets').textContent = data.stats.total_packets;
                document.getElementById('tcpCount').textContent = data.stats.tcp_count;
                document.getElementById('udpCount').textContent = data.stats.udp_count;
                document.getElementById('dnsCount').textContent = data.stats.dns_count;
                document.getElementById('icmpCount').textContent = data.stats.icmp_count;
                
                const avgSize = data.stats.packet_sizes.length > 0 
                    ? Math.round(data.stats.packet_sizes.reduce((a,b) => a+b, 0) / data.stats.packet_sizes.length)
                    : 0;
                document.getElementById('avgSize').textContent = avgSize + ' B';

                // Update protocol chart
                const protocols = data.stats.protocols;
                if (protocolChart) protocolChart.destroy();
                protocolChart = new Chart(document.getElementById('protocolChart'), {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(protocols),
                        datasets: [{
                            data: Object.values(protocols),
                            backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                        }]
                    },
                    options: {responsive: true}
                });

                // Update size chart
                if (data.stats.packet_sizes.length > 0) {
                    const sizeBuckets = {
                        '0-100': 0, '100-500': 0, '500-1000': 0, '1000-5000': 0, '5000+': 0
                    };
                    data.stats.packet_sizes.forEach(size => {
                        if (size < 100) sizeBuckets['0-100']++;
                        else if (size < 500) sizeBuckets['100-500']++;
                        else if (size < 1000) sizeBuckets['500-1000']++;
                        else if (size < 5000) sizeBuckets['1000-5000']++;
                        else sizeBuckets['5000+']++;
                    });
                    
                    if (sizeChart) sizeChart.destroy();
                    sizeChart = new Chart(document.getElementById('sizeChart'), {
                        type: 'bar',
                        data: {
                            labels: Object.keys(sizeBuckets),
                            datasets: [{
                                label: 'Packets',
                                data: Object.values(sizeBuckets),
                                backgroundColor: '#667eea'
                            }]
                        },
                        options: {responsive: true, plugins: {legend: {display: false}}}
                    });
                }

                // Top source IPs
                const topSrc = Object.entries(data.stats.src_ips)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5);
                
                if (srcChart) srcChart.destroy();
                srcChart = new Chart(document.getElementById('srcChart'), {
                    type: 'bar',
                    data: {
                        labels: topSrc.map(x => x[0]),
                        datasets: [{
                            label: 'Packets',
                            data: topSrc.map(x => x[1]),
                            backgroundColor: '#764ba2'
                        }]
                    },
                    options: {indexAxis: 'y', responsive: true, plugins: {legend: {display: false}}}
                });

                // Top destination IPs
                const topDst = Object.entries(data.stats.dst_ips)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5);
                
                if (dstChart) dstChart.destroy();
                dstChart = new Chart(document.getElementById('dstChart'), {
                    type: 'bar',
                    data: {
                        labels: topDst.map(x => x[0]),
                        datasets: [{
                            label: 'Packets',
                            data: topDst.map(x => x[1]),
                            backgroundColor: '#36A2EB'
                        }]
                    },
                    options: {indexAxis: 'y', responsive: true, plugins: {legend: {display: false}}}
                });

                // Update packet table
                const tbody = document.getElementById('packetBody');
                tbody.innerHTML = '';
                data.packets.slice(-20).reverse().forEach(pkt => {
                    const row = `<tr>
                        <td>${pkt.timestamp}</td>
                        <td>${pkt.src_ip}</td>
                        <td>${pkt.dst_ip}</td>
                        <td><strong>${pkt.protocol}</strong></td>
                        <td>${pkt.size}</td>
                        <td>${pkt.details}</td>
                    </tr>`;
                    tbody.innerHTML += row;
                });
            } catch (err) {
                console.error('Error:', err);
            }
        }

        // Update every 2 seconds
        updateData();
        setInterval(updateData, 2000);
    </script>
</body>
</html>"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'packets': packets,
        'stats': {
            'total_packets': stats['total_packets'],
            'tcp_count': stats['tcp_count'],
            'udp_count': stats['udp_count'],
            'icmp_count': stats['icmp_count'],
            'dns_count': stats['dns_count'],
            'other_count': stats['other_count'],
            'src_ips': dict(stats['src_ips']),
            'dst_ips': dict(stats['dst_ips']),
            'protocols': dict(stats['protocols']),
            'packet_sizes': stats['packet_sizes'][-1000:]
        }
    })

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
