# Network Traffic Analyzer

Real-time network packet capture and protocol analysis with interactive dashboard.

## Features

- **Live Packet Capture**: Real-time packet sniffing using Scapy
- **Protocol Analysis**: TCP, UDP, DNS, ICMP detection and breakdown
- **Traffic Visualization**: Interactive charts for protocols, packet sizes, IPs
- **Live Dashboard**: Real-time metrics and latest packet details
- **IP Tracking**: Top source and destination IPs

## Tech Stack

- **Backend**: Flask, Python, Scapy
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js
- **Deployment**: Render

## How It Works

1. Captures network packets in real-time using Scapy
2. Analyzes protocol types (TCP, UDP, DNS, ICMP)
3. Tracks source/destination IPs and packet sizes
4. Displays real-time charts and metrics via Flask API
5. Updates dashboard every 2 seconds

## Live Demo

[Network Traffic Analyzer](https://network-traffic-analyzer-1.onrender.com)


## API

**GET /api/stats** - Returns real-time traffic statistics and packet data

## Author

[Joydeepa Banik](https://github.com/JoydeepaB)
