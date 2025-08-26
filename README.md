# PacketSight - Professional Network Traffic Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/Scapy-2.5.0-red.svg)](https://scapy.net/)

**Developed by:** [sharondelya](https://github.com/sharondelya)

A comprehensive, professional-grade network traffic analyzer with real-time monitoring capabilities, PCAP file analysis, and advanced visualization features. Built with Flask, Scapy, and modern web technologies.

## 🚀 Features

### Core Functionality
- **Real-time Network Monitoring** - Live packet capture from network interfaces
- **PCAP File Analysis** - Upload and analyze Wireshark/tcpdump capture files (.pcap, .pcapng, .cap)
- **Protocol Support** - TCP, UDP, HTTP/HTTPS, DNS, ICMP analysis with deep packet inspection
- **Flow Analysis** - Connection flow tracking and session analysis
- **Database Storage** - SQLite/PostgreSQL support with persistent data storage

### Advanced Analytics
- **Interactive Visualizations** - Real-time charts using Chart.js and Plotly.js
- **Security Analysis** - Threat detection and security indicators
- **Protocol Distribution** - Detailed protocol usage statistics
- **Geographic Analysis** - IP geolocation and traffic distribution mapping
- **Port Analysis** - Service identification and port activity monitoring
- **Top Talkers** - Most active hosts and traffic patterns

### Professional Interface
- **Modern Web Dashboard** - Clean, responsive interface with Bootstrap 5
- **Real-time Updates** - Live data refresh with WebSocket-like functionality
- **Advanced Filtering** - Comprehensive search and filter options
- **Data Export** - Export capabilities for analysis results
- **Mobile Responsive** - Works on desktop, tablet, and mobile devices

## 📋 Prerequisites

- **Python 3.8 or higher**
- **Modern web browser** (Chrome, Firefox, Safari, Edge)
- **Network interface access** (for live packet capture)
- **Administrative privileges** (recommended for packet capture)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/sharondelya/PacketSight.git
cd PacketSight
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize Database
```bash
python init_db.py
```

### 5. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 🐳 Docker Deployment

### Build and Run with Docker
```bash
# Build the image
docker build -t packetsight .

# Run the container
docker run -p 5000:5000 --cap-add=NET_ADMIN packetsight
```

### Docker Compose
```bash
docker-compose up -d
```

## 📁 Project Structure

```
PacketSight/
├── app.py                 # Main Flask application
├── models.py             # Database models
├── routes.py             # Web routes and API endpoints
├── pcap_parser.py        # PCAP file parsing functionality
├── real_packet_capture.py # Live packet capture
├── network_analyzer.py   # Network analysis engine
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose setup
├── templates/           # HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── packets.html
│   ├── flows.html
│   ├── analytics.html
│   └── upload.html
├── static/              # Static assets
│   ├── css/
│   ├── js/
│   └── images/
└── instance/            # Instance-specific files
    └── uploads/         # Uploaded PCAP files
```

## 🏗️ Architecture Overview

PacketSight follows a modular architecture with clear separation of concerns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Frontend  │    │  Flask Backend  │    │    Database     │
│                 │    │                 │    │                 │
│ • Dashboard     │◄──►│ • Routes        │◄──►│ • SQLite/       │
│ • Analytics     │    │ • API Endpoints │    │   PostgreSQL    │
│ • Upload UI     │    │ • Data Models   │    │ • Real Data     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │ Network Capture │
                       │                 │
                       │ • Live Capture  │
                       │ • PCAP Parser   │
                       │ • Protocol      │
                       │   Analysis      │
                       └─────────────────┘
```

### Key Design Principles
- **Real Data Only**: No mock or dummy data in production
- **Modular Design**: Clear separation between components
- **Scalable**: Designed to handle large datasets
- **Professional**: Production-ready code quality
- **Extensible**: Easy to add new features

## 🔧 Configuration

### Environment Variables
```bash
# Database Configuration
DATABASE_URL=sqlite:///network_analyzer.db
# or for PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost/packetsight

# Security
SESSION_SECRET=your-secret-key-here

# Application Settings
FLASK_ENV=production
FLASK_DEBUG=False
```

### Configuration File (config.py)
```python
class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///network_analyzer.db'
    SECRET_KEY = 'your-secret-key'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size
```

## 📊 Usage

### 1. Live Packet Capture
- Click "Start Capture" in the status bar
- Monitor real-time traffic on the dashboard
- View detailed packet information in the Packets tab
- Analyze network flows in the Flows tab

### 2. PCAP File Analysis
- Navigate to "Upload PCAP" in the navigation menu
- Select a .pcap, .pcapng, or .cap file
- Configure parsing options (max packets, etc.)
- Upload and analyze the file
- View results in Dashboard, Packets, Flows, and Analytics

### 3. Analytics and Visualization
- **Dashboard**: Overview of network activity and statistics
- **Packets**: Detailed packet-level analysis with filtering
- **Flows**: Network flow analysis and connection tracking
- **Analytics**: Advanced visualizations and security analysis

## 🔍 Features in Detail

### PCAP File Support
- **Formats**: .pcap, .pcapng, .cap files
- **Sources**: Wireshark, tcpdump, tshark, and other capture tools
- **Parsing**: Deep packet inspection with protocol analysis
- **Performance**: Optimized for large files with configurable limits

### Real-time Monitoring
- **Live Capture**: Direct network interface monitoring
- **Protocol Detection**: Automatic protocol identification
- **Flow Tracking**: Connection state monitoring
- **Performance Metrics**: Bandwidth and throughput analysis

### Security Analysis
- **Threat Detection**: Suspicious activity identification
- **Geographic Analysis**: IP geolocation and risk assessment
- **Port Scanning**: Unusual port activity detection
- **Protocol Anomalies**: Abnormal protocol usage patterns

## 🚀 API Endpoints

### Statistics API
```
GET /api/stats                    # Real-time statistics
GET /api/protocol-distribution    # Protocol usage data
GET /api/traffic-timeline        # Traffic over time
GET /api/top-talkers             # Most active hosts
GET /api/port-analysis           # Port activity analysis
GET /api/geo-analysis            # Geographic distribution
```

### Capture Control API
```
POST /api/start-capture          # Start live capture
POST /api/stop-capture           # Stop live capture
GET  /capture-status             # Capture status
```

### File Upload API
```
POST /api/upload-pcap            # Upload and parse PCAP file
POST /api/validate-pcap          # Validate PCAP file
```

## 🧪 Testing

### Run Tests
```bash
python -m pytest tests/
```

### Test Coverage
```bash
python -m pytest --cov=. tests/
```

### Manual Testing
```bash
python test_functionality.py
```

## 🔒 Security Considerations

### Network Capture Permissions
- **Linux**: Requires `CAP_NET_RAW` capability or root privileges
- **Windows**: Requires Administrator privileges
- **macOS**: Requires root privileges or specific permissions

### File Upload Security
- File type validation
- Size limits (configurable)
- Temporary file cleanup
- Secure filename handling

### Database Security
- SQL injection prevention
- Input validation
- Secure session management

## 📈 Performance Optimization

### Database Optimization
- Indexed queries for fast lookups
- Automatic data cleanup for old records
- Connection pooling for concurrent access
- Optimized schema design

### Memory Management
- Streaming PCAP file processing
- Configurable packet limits
- Efficient data structures
- Garbage collection optimization

### Web Performance
- Asynchronous data loading
- Compressed static assets
- CDN integration for libraries
- Responsive design optimization

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run in development mode
export FLASK_ENV=development
python app.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy** - Powerful packet manipulation library
- **Flask** - Lightweight web framework
- **Chart.js** - Beautiful charts and visualizations
- **Bootstrap** - Responsive UI framework
- **Font Awesome** - Icon library

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/sharondelya/PacketSight/issues)
- **Documentation**: [Wiki](https://github.com/sharondelya/PacketSight/wiki)
- **Email**: support@packetsight.dev

## 🗺️ Roadmap

### Version 2.0 (Planned)
- [ ] Machine Learning-based anomaly detection
- [ ] WebSocket real-time updates
- [ ] Advanced threat intelligence integration
- [ ] Custom rule engine
- [ ] Multi-interface capture support
- [ ] Advanced export formats (JSON, XML, CSV)
- [ ] User authentication and role-based access
- [ ] API rate limiting and authentication

### Version 2.1 (Future)
- [ ] Distributed capture across multiple nodes
- [ ] Integration with SIEM systems
- [ ] Advanced packet reconstruction
- [ ] Custom protocol parsers
- [ ] Performance benchmarking tools

---

**Built with ❤️ by [sharondelya](https://github.com/sharondelya)**

*Professional Network Traffic Analysis Made Simple*