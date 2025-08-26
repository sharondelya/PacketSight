"""
Database models for Network Traffic Analyzer
Author: sharondelya
Description: SQLAlchemy models for storing network packets, flows, and statistics
"""

from datetime import datetime
from app import db


class Packet(db.Model):
    """Model for storing individual network packets"""
    __tablename__ = 'packets'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)  # IPv4/IPv6
    dest_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    dest_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(20), nullable=False, index=True)  # TCP, UDP, ICMP, etc.
    packet_size = db.Column(db.Integer, nullable=False)
    payload_size = db.Column(db.Integer, nullable=False, default=0)
    flags = db.Column(db.String(50), nullable=True)  # TCP flags
    ttl = db.Column(db.Integer, nullable=True)
    payload_preview = db.Column(db.Text, nullable=True)  # First 200 chars of payload
    
    def __repr__(self):
        return f'<Packet {self.source_ip}:{self.source_port} -> {self.dest_ip}:{self.dest_port} ({self.protocol})>'
    
    def to_dict(self):
        """Convert packet to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'payload_size': self.payload_size,
            'flags': self.flags,
            'ttl': self.ttl,
            'payload_preview': self.payload_preview
        }


class Flow(db.Model):
    """Model for storing network flows (connections)"""
    __tablename__ = 'flows'
    
    id = db.Column(db.Integer, primary_key=True)
    flow_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=False)
    dest_port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(20), nullable=False, index=True)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)  # Duration in seconds
    packet_count = db.Column(db.Integer, nullable=False, default=0)
    total_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default='ACTIVE', index=True)  # ACTIVE, CLOSED, TIMEOUT
    
    def __repr__(self):
        return f'<Flow {self.flow_id}: {self.source_ip}:{self.source_port} -> {self.dest_ip}:{self.dest_port}>'
    
    def to_dict(self):
        """Convert flow to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'flow_id': self.flow_id,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'status': self.status
        }


class DNSQuery(db.Model):
    """Model for storing DNS queries and responses"""
    __tablename__ = 'dns_queries'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45), nullable=False, index=True)
    query_name = db.Column(db.String(255), nullable=False, index=True)
    query_type = db.Column(db.String(10), nullable=False)  # A, AAAA, CNAME, MX, etc.
    response_code = db.Column(db.Integer, nullable=True)  # 0 = success, 3 = NXDOMAIN, etc.
    response_time = db.Column(db.Float, nullable=True)  # Response time in milliseconds
    response_data = db.Column(db.Text, nullable=True)  # Response data (IP addresses, etc.)
    is_cached = db.Column(db.Boolean, nullable=False, default=False)
    
    def __repr__(self):
        return f'<DNSQuery {self.query_name} ({self.query_type})>'
    
    def to_dict(self):
        """Convert DNS query to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'query_name': self.query_name,
            'query_type': self.query_type,
            'response_code': self.response_code,
            'response_time': self.response_time,
            'response_data': self.response_data,
            'is_cached': self.is_cached
        }


class HTTPTransaction(db.Model):
    """Model for storing HTTP requests and responses"""
    __tablename__ = 'http_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45), nullable=False, index=True)
    method = db.Column(db.String(10), nullable=False, index=True)  # GET, POST, PUT, etc.
    url = db.Column(db.Text, nullable=False)
    host = db.Column(db.String(255), nullable=True, index=True)
    status_code = db.Column(db.Integer, nullable=True, index=True)  # 200, 404, 500, etc.
    response_time = db.Column(db.Float, nullable=True)  # Response time in milliseconds
    request_size = db.Column(db.Integer, nullable=True)
    response_size = db.Column(db.Integer, nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    content_type = db.Column(db.String(100), nullable=True)
    is_ssl = db.Column(db.Boolean, nullable=False, default=False)
    
    def __repr__(self):
        return f'<HTTPTransaction {self.method} {self.url}>'
    
    def to_dict(self):
        """Convert HTTP transaction to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'method': self.method,
            'url': self.url,
            'host': self.host,
            'status_code': self.status_code,
            'response_time': self.response_time,
            'request_size': self.request_size,
            'response_size': self.response_size,
            'user_agent': self.user_agent,
            'content_type': self.content_type,
            'is_ssl': self.is_ssl
        }


class NetworkStatistics(db.Model):
    """Model for storing aggregated network statistics"""
    __tablename__ = 'network_statistics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    metric_name = db.Column(db.String(50), nullable=False, index=True)
    metric_value = db.Column(db.Float, nullable=False)
    metric_unit = db.Column(db.String(20), nullable=True)
    category = db.Column(db.String(30), nullable=False, index=True)  # TRAFFIC, SECURITY, PERFORMANCE
    protocol = db.Column(db.String(20), nullable=True, index=True)
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    dest_ip = db.Column(db.String(45), nullable=True, index=True)
    
    def __repr__(self):
        return f'<NetworkStatistics {self.metric_name}: {self.metric_value} {self.metric_unit}>'
    
    def to_dict(self):
        """Convert network statistics to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'metric_name': self.metric_name,
            'metric_value': self.metric_value,
            'metric_unit': self.metric_unit,
            'category': self.category,
            'protocol': self.protocol,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip
        }