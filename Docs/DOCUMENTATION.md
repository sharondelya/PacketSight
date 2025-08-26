# PacketSight - Technical Documentation

## 📋 Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Database Schema](#database-schema)
4. [API Reference](#api-reference)
5. [File Structure](#file-structure)
6. [Configuration](#configuration)
7. [Development Guide](#development-guide)
8. [Testing](#testing)
9. [Performance](#performance)
10. [Security](#security)

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

## 🔧 Core Components

### 1. Flask Application (`app.py`)
Main application factory with configuration and initialization.

```python
def create_app():
    """Application factory pattern for creating Flask app"""
    app = Flask(__name__)
    
    # Configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Initialize extensions
    db.init_app(app)
    
    # Register routes
    from routes import init_routes
    init_routes(app)
    
    return app
```

### 2. Database Models (`models.py`)
SQLAlchemy models for network data storage.

#### Core Models:
- **Packet**: Individual network packets
- **Flow**: Network connection flows
- **DNSQuery**: DNS query records
- **HTTPTransaction**: HTTP request/response pairs
- **NetworkStatistics**: Aggregated statistics

### 3. PCAP Parser (`pcap_parser.py`)
Professional PCAP file parsing with Scapy integration.

```python
class PCAPParser:
    def parse_file(self, file_path, max_packets=None):
        """Parse PCAP file and extract network data"""
        packets = rdpcap(file_path)
        # Process packets and extract protocols
        return parsed_data
```

### 4. Network Analyzer (`network_analyzer.py`)
Advanced analytics and pattern detection.

### 5. Real-time Capture (`real_packet_capture.py`)
Live network packet capture functionality.

## 🗄️ Database Schema

### Packets Table
```sql
CREATE TABLE packets (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    source_port INTEGER,
    dest_port INTEGER,
    protocol VARCHAR(20) NOT NULL,
    packet_size INTEGER NOT NULL,
    payload_size INTEGER,
    flags VARCHAR(50),
    ttl INTEGER,
    payload_preview TEXT
);
```

### Flows Table
```sql
CREATE TABLE flows (
    id INTEGER PRIMARY KEY,
    flow_id VARCHAR(32) UNIQUE NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    source_port INTEGER NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration FLOAT,
    packet_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);
```

### DNS Queries Table
```sql
CREATE TABLE dns_queries (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    query_type VARCHAR(10) NOT NULL,
    response_code INTEGER,
    response_time FLOAT,
    response_data TEXT,
    is_cached BOOLEAN DEFAULT FALSE
);
```

### HTTP Transactions Table
```sql
CREATE TABLE http_transactions (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    method VARCHAR(10) NOT NULL,
    url TEXT NOT NULL,
    host VARCHAR(255),
    status_code INTEGER,
    response_time FLOAT,
    request_size INTEGER,
    response_size INTEGER,
    user_agent TEXT,
    content_type VARCHAR(100),
    is_ssl BOOLEAN DEFAULT FALSE
);
```

## 🔌 API Reference

### Statistics Endpoints

#### GET /api/stats
Returns real-time system statistics.

**Response:**
```json
{
    "total_packets": 15420,
    "total_flows": 342,
    "active_flows": 23,
    "recent_packets": 1250,
    "timestamp": "2023-12-07T10:30:00Z"
}
```

#### GET /api/protocol-distribution
Returns protocol usage statistics.

**Response:**
```json
[
    {"protocol": "TCP", "packets": 8500, "bytes": 12500000},
    {"protocol": "UDP", "packets": 3200, "bytes": 2100000},
    {"protocol": "HTTP", "packets": 2100, "bytes": 8900000}
]
```

#### GET /api/traffic-timeline
Returns traffic data over time.

**Parameters:**
- `hours` (optional): Time range in hours (default: 24)

**Response:**
```json
[
    {
        "timestamp": "2023-12-07T09:00:00Z",
        "packets": 450,
        "bytes": 650000
    }
]
```

### Capture Control Endpoints

#### POST /api/start-capture
Start live packet capture.

**Request Body:**
```json
{
    "interface": "auto",
    "duration": null
}
```

#### POST /api/stop-capture
Stop active packet capture.

#### GET /capture-status
Get current capture status.

### File Upload Endpoints

#### POST /api/upload-pcap
Upload and parse PCAP file.

**Form Data:**
- `file`: PCAP file (.pcap, .pcapng, .cap)
- `max_packets`: Maximum packets to process (optional)

**Response:**
```json
{
    "success": true,
    "message": "Successfully parsed 5000 packets",
    "file_info": {
        "packet_count": 5000,
        "file_size_mb": 15.2,
        "duration": 300.5
    },
    "parse_results": {
        "parsed_packets": 5000,
        "protocols": {"TCP": 3000, "UDP": 1500, "HTTP": 500}
    }
}
```

## 📁 File Structure

```
PacketSight/
├── app.py                    # Main Flask application
├── models.py                 # Database models
├── simple_models.py          # Simplified model imports
├── routes.py                 # Web routes and API endpoints
├── pcap_parser.py           # PCAP file parsing
├── real_packet_capture.py   # Live packet capture
├── network_analyzer.py      # Network analysis engine
├── database_manager.py      # Database utilities
├── config.py                # Configuration settings
├── init_db.py               # Database initialization
├── requirements.txt         # Python dependencies
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose setup
├── README.md               # Main documentation
├── DEPLOYMENT.md           # Deployment guide
├── DOCUMENTATION.md        # Technical documentation
├── templates/              # HTML templates
│   ├── base.html          # Base template
│   ├── dashboard.html     # Main dashboard
│   ├── packets.html       # Packet analysis
│   ├── flows.html         # Flow analysis
│   ├── analytics.html     # Advanced analytics
│   └── upload.html        # PCAP upload interface
├── static/                # Static assets
│   ├── css/
│   │   └── style.css      # Custom styles
│   ├── js/
│   │   ├── dashboard.js   # Dashboard functionality
│   │   ├── charts.js      # Chart configurations
│   │   └── analytics.js   # Analytics features
│   └── images/            # Image assets
└── instance/              # Instance-specific files
    ├── uploads/           # Uploaded PCAP files
    └── temp/              # Temporary files
```

## ⚙️ Configuration

### Environment Variables
```bash
# Database Configuration
DATABASE_URL=sqlite:///network_analyzer.db
# or PostgreSQL: postgresql://user:pass@host:5432/db

# Security
SESSION_SECRET=your-secret-key-here

# Application Settings
FLASK_ENV=production
FLASK_DEBUG=False
MAX_UPLOAD_SIZE=104857600  # 100MB
MAX_PACKETS_PER_UPLOAD=10000

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/packetsight.log
```

### Configuration Classes
```python
class Config:
    SECRET_KEY = os.environ.get('SESSION_SECRET')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///dev_network_analyzer.db'

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
```

## 👨‍💻 Development Guide

### Setting Up Development Environment

1. **Clone Repository**
```bash
git clone https://github.com/sharondelya/PacketSight.git
cd PacketSight
```

2. **Create Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Initialize Database**
```bash
python init_db.py
```

5. **Run Development Server**
```bash
export FLASK_ENV=development  # Linux/macOS
set FLASK_ENV=development     # Windows
python app.py
```

### Code Style Guidelines

- **PEP 8**: Follow Python style guidelines
- **Type Hints**: Use type hints where appropriate
- **Docstrings**: Document all functions and classes
- **Error Handling**: Comprehensive exception handling
- **Logging**: Use structured logging throughout

### Adding New Features

1. **Database Changes**
   - Update models in `models.py`
   - Create migration script
   - Update `init_db.py` if needed

2. **API Endpoints**
   - Add routes in `routes.py`
   - Follow RESTful conventions
   - Include proper error handling

3. **Frontend Changes**
   - Update templates in `templates/`
   - Add JavaScript in `static/js/`
   - Follow Bootstrap conventions

## 🧪 Testing

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-cov pytest-flask

# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=.

# Run specific test file
python -m pytest tests/test_api.py
```

### Test Structure
```
tests/
├── conftest.py              # Test configuration
├── test_models.py           # Database model tests
├── test_api.py              # API endpoint tests
├── test_pcap_parser.py      # PCAP parsing tests
├── test_capture.py          # Packet capture tests
└── fixtures/                # Test data files
    ├── sample.pcap
    └── test_data.json
```

### Writing Tests
```python
def test_packet_creation(app, db):
    """Test packet model creation"""
    with app.app_context():
        packet = Packet(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.1',
            dest_ip='8.8.8.8',
            protocol='TCP',
            packet_size=64
        )
        db.session.add(packet)
        db.session.commit()
        
        assert packet.id is not None
        assert packet.source_ip == '192.168.1.1'
```

## 📊 Performance

### Database Optimization
- **Indexes**: Strategic indexing on frequently queried columns
- **Connection Pooling**: Efficient database connection management
- **Query Optimization**: Optimized SQL queries with proper joins
- **Data Cleanup**: Automatic cleanup of old data

### Application Performance
- **Caching**: Redis caching for frequently accessed data
- **Async Processing**: Background processing for heavy operations
- **Memory Management**: Efficient memory usage for large datasets
- **Static Assets**: CDN integration for static files

### Monitoring
```python
# Performance monitoring
import time
import psutil

def monitor_performance():
    cpu_percent = psutil.cpu_percent()
    memory_info = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')
    
    return {
        'cpu_percent': cpu_percent,
        'memory_percent': memory_info.percent,
        'disk_percent': disk_usage.percent
    }
```

## 🔒 Security

### Input Validation
- **File Upload**: Strict file type and size validation
- **SQL Injection**: Parameterized queries with SQLAlchemy
- **XSS Prevention**: Template escaping and CSP headers
- **CSRF Protection**: CSRF tokens for forms

### Authentication & Authorization
```python
from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
```

### Security Headers
```python
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

### Data Protection
- **Encryption**: Sensitive data encryption at rest
- **Secure Sessions**: Secure session configuration
- **Rate Limiting**: API rate limiting to prevent abuse
- **Audit Logging**: Comprehensive audit trail

---

**For additional technical details, please refer to the source code comments and docstrings.**