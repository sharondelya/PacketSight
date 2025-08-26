# PacketSight Deployment Guide

This guide provides comprehensive instructions for deploying PacketSight in various environments.

## 🚀 Quick Start (Local Development)

### Prerequisites
- Python 3.8+
- Git
- Virtual environment support

### Steps
```bash
# 1. Clone the repository
git clone https://github.com/sharondelya/PacketSight.git
cd PacketSight

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize database
python init_db.py

# 5. Run the application
python app.py
```

Access the application at `http://localhost:5000`

## 🐳 Docker Deployment

### Simple Docker Run
```bash
# Build the image
docker build -t packetsight .

# Run with SQLite (development)
docker run -p 5000:5000 --cap-add=NET_ADMIN packetsight

# Run with PostgreSQL (production)
docker run -p 5000:5000 \
  --cap-add=NET_ADMIN \
  -e DATABASE_URL=postgresql://user:pass@host:5432/db \
  packetsight
```

### Docker Compose (Recommended)
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## ☁️ Cloud Deployment

### AWS EC2 Deployment

#### 1. Launch EC2 Instance
- **Instance Type**: t3.medium or larger
- **AMI**: Ubuntu 20.04 LTS
- **Security Group**: Allow ports 22, 80, 443, 5000
- **Storage**: 20GB+ EBS volume

#### 2. Setup Instance
```bash
# Connect to instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Clone and deploy
git clone https://github.com/sharondelya/PacketSight.git
cd PacketSight
docker-compose up -d
```

#### 3. Configure Security
```bash
# Setup firewall
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable

# Setup SSL with Let's Encrypt (optional)
sudo apt install certbot
sudo certbot --nginx -d your-domain.com
```

### Google Cloud Platform (GCP)

#### 1. Create VM Instance
```bash
# Using gcloud CLI
gcloud compute instances create packetsight-vm \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --machine-type=e2-medium \
  --zone=us-central1-a \
  --tags=http-server,https-server
```

#### 2. Deploy Application
```bash
# SSH to instance
gcloud compute ssh packetsight-vm

# Follow same Docker setup as AWS
```

### Azure Deployment

#### 1. Create Virtual Machine
```bash
# Using Azure CLI
az vm create \
  --resource-group myResourceGroup \
  --name packetsight-vm \
  --image UbuntuLTS \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys
```

#### 2. Configure Network Security
```bash
# Open ports
az vm open-port --port 80 --resource-group myResourceGroup --name packetsight-vm
az vm open-port --port 443 --resource-group myResourceGroup --name packetsight-vm
```

## 🔧 Production Configuration

### Environment Variables
Create a `.env` file:
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/packetsight

# Security
SESSION_SECRET=your-super-secret-key-here
FLASK_ENV=production
FLASK_DEBUG=False

# Application
MAX_UPLOAD_SIZE=104857600  # 100MB
MAX_PACKETS_PER_UPLOAD=10000

# Logging
LOG_LEVEL=INFO
LOG_FILE=/app/logs/packetsight.log

# Redis (optional)
REDIS_URL=redis://localhost:6379/0
```

### Database Setup (PostgreSQL)
```sql
-- Create database and user
CREATE DATABASE packetsight;
CREATE USER packetsight WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE packetsight TO packetsight;

-- Connect to database
\c packetsight

-- Create extensions (optional)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
```

### Nginx Configuration
```nginx
# /etc/nginx/sites-available/packetsight
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # File Upload Size
    client_max_body_size 100M;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Static files
    location /static {
        alias /app/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### Systemd Service (Alternative to Docker)
```ini
# /etc/systemd/system/packetsight.service
[Unit]
Description=PacketSight Network Traffic Analyzer
After=network.target

[Service]
Type=exec
User=packetsight
Group=packetsight
WorkingDirectory=/opt/packetsight
Environment=PATH=/opt/packetsight/venv/bin
ExecStart=/opt/packetsight/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 📊 Monitoring and Logging

### Application Monitoring
```python
# Add to config.py
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
if not app.debug:
    file_handler = RotatingFileHandler('logs/packetsight.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
```

### System Monitoring
```bash
# Install monitoring tools
sudo apt install htop iotop nethogs

# Monitor application
htop
docker stats  # For Docker deployment
journalctl -u packetsight -f  # For systemd service
```

### Log Rotation
```bash
# /etc/logrotate.d/packetsight
/app/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 packetsight packetsight
    postrotate
        systemctl reload packetsight
    endscript
}
```

## 🔒 Security Hardening

### Application Security
1. **Change default secrets**
2. **Use HTTPS in production**
3. **Implement rate limiting**
4. **Regular security updates**
5. **Input validation and sanitization**

### System Security
```bash
# Update system regularly
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443

# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Install fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

## 🚨 Troubleshooting

### Common Issues

#### Permission Denied for Packet Capture
```bash
# Solution 1: Run with sudo (not recommended for production)
sudo python app.py

# Solution 2: Set capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)

# Solution 3: Add user to netdev group
sudo usermod -a -G netdev $USER
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
psql -h localhost -U packetsight -d packetsight

# Reset database
python init_db.py --reset
```

#### High Memory Usage
```bash
# Monitor memory usage
free -h
ps aux | grep python

# Optimize configuration
# Reduce MAX_PACKETS_PER_UPLOAD in config
# Implement data cleanup policies
```

### Performance Tuning

#### Database Optimization
```sql
-- Add indexes for better performance
CREATE INDEX idx_packets_timestamp ON packets(timestamp);
CREATE INDEX idx_packets_protocol ON packets(protocol);
CREATE INDEX idx_flows_start_time ON flows(start_time);
```

#### Application Tuning
```python
# config.py
class ProductionConfig:
    # Database connection pooling
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'max_overflow': 30
    }
    
    # File upload limits
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    
    # Caching
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = 'redis://localhost:6379/0'
```

## 📈 Scaling

### Horizontal Scaling
- Use load balancer (nginx, HAProxy)
- Deploy multiple application instances
- Shared database and Redis
- Container orchestration (Kubernetes)

### Vertical Scaling
- Increase server resources (CPU, RAM)
- Optimize database queries
- Implement caching strategies
- Use CDN for static assets

## 🔄 Backup and Recovery

### Database Backup
```bash
# PostgreSQL backup
pg_dump -h localhost -U packetsight packetsight > backup.sql

# Restore
psql -h localhost -U packetsight packetsight < backup.sql

# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -h localhost -U packetsight packetsight | gzip > /backups/packetsight_$DATE.sql.gz
find /backups -name "packetsight_*.sql.gz" -mtime +7 -delete
```

### Application Backup
```bash
# Backup configuration and data
tar -czf packetsight_backup_$(date +%Y%m%d).tar.gz \
  /opt/packetsight/instance \
  /opt/packetsight/.env \
  /opt/packetsight/logs
```

---

**For additional support, please refer to the main README.md or create an issue on GitHub.**