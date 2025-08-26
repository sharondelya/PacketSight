"""
Simple Database models for Network Traffic Analyzer
Author: sharondelya
Description: Simple SQLAlchemy models without circular imports
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

# Create the database instance
db = SQLAlchemy(model_class=Base)

class Packet(db.Model):
    """Model for storing individual network packets"""
    __tablename__ = 'packets'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    dest_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), nullable=False, index=True)
    packet_size = db.Column(db.Integer, nullable=False)
    payload_size = db.Column(db.Integer, nullable=False, default=0)
    flags = db.Column(db.String(20), nullable=True)
    ttl = db.Column(db.Integer, nullable=True)
    payload_preview = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Packet {self.source_ip}:{self.source_port} -> {self.dest_ip}:{self.dest_port} ({self.protocol})>'

class Flow(db.Model):
    """Model for storing network flows"""
    __tablename__ = 'flows'
    
    id = db.Column(db.Integer, primary_key=True)
    flow_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    dest_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), nullable=False, index=True)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)
    packet_count = db.Column(db.Integer, default=0)
    total_bytes = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='ACTIVE')
    
    def __repr__(self):
        return f'<Flow {self.flow_id}: {self.source_ip}:{self.source_port} <-> {self.dest_ip}:{self.dest_port}>'

class NetworkStatistics(db.Model):
    """Model for storing network statistics"""
    __tablename__ = 'network_statistics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    metric_name = db.Column(db.String(50), nullable=False, index=True)
    metric_value = db.Column(db.Float, nullable=False)
    metric_unit = db.Column(db.String(20), nullable=True)
    category = db.Column(db.String(30), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    
    def __repr__(self):
        return f'<NetworkStatistics {self.metric_name}: {self.metric_value}>'

class DNSQuery(db.Model):
    """Model for storing DNS queries"""
    __tablename__ = 'dns_queries'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45), nullable=True)  # Allow NULL
    query_name = db.Column(db.String(255), nullable=False, index=True)
    query_type = db.Column(db.String(10), nullable=False)
    response_code = db.Column(db.Integer, nullable=True)
    response_data = db.Column(db.Text, nullable=True)
    response_time = db.Column(db.Float, nullable=True)
    is_cached = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<DNSQuery {self.query_name} ({self.query_type})>'

class HTTPTransaction(db.Model):
    """Model for storing HTTP transactions"""
    __tablename__ = 'http_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45), nullable=False, index=True)
    method = db.Column(db.String(10), nullable=False)
    url = db.Column(db.Text, nullable=False)
    host = db.Column(db.String(255), nullable=True, index=True)
    status_code = db.Column(db.Integer, nullable=True)
    response_time = db.Column(db.Float, nullable=True)
    request_size = db.Column(db.Integer, nullable=True)
    response_size = db.Column(db.Integer, nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    content_type = db.Column(db.String(100), nullable=True)
    is_ssl = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<HTTPTransaction {self.method} {self.url}>'