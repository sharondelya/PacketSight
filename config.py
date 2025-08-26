"""
Configuration settings for Network Traffic Analyzer
Author: sharondelya
Description: Application configuration and environment variables
"""

import os
from datetime import timedelta


class Config:
    """Base configuration class"""
    
    # Secret key for sessions and security
    SECRET_KEY = os.environ.get('SESSION_SECRET') or 'sharondelya-network-analyzer-dev-key'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///network_analyzer.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # Application settings
    PACKETS_PER_PAGE = 50
    FLOWS_PER_PAGE = 25
    MAX_PACKET_PAYLOAD_PREVIEW = 200
    
    # Simulation settings
    SIMULATION_ENABLED = True
    DEFAULT_SIMULATION_INTERVAL = 30  # seconds
    MAX_SIMULATION_PACKETS = 1000
    
    # Analytics settings
    ANALYTICS_RETENTION_DAYS = 30
    STATISTICS_UPDATE_INTERVAL = 60  # seconds
    
    # Security settings
    SECURITY_MONITORING_ENABLED = True
    ALERT_THRESHOLDS = {
        'packets_per_second': 1000,
        'bytes_per_second': 10485760,  # 10 MB
        'failed_connections': 50,
        'suspicious_ports': [22, 23, 3389, 1433, 3306]
    }
    
    # Network interface settings
    DEFAULT_INTERFACE = 'eth0'
    PROMISCUOUS_MODE = False
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = 'network_analyzer.log'
    
    # Web interface settings
    WEB_HOST = '0.0.0.0'
    WEB_PORT = 5000
    DEBUG_MODE = os.environ.get('FLASK_ENV') == 'development'
    
    # Data export settings
    EXPORT_FORMATS = ['JSON', 'CSV', 'PCAP']
    MAX_EXPORT_RECORDS = 10000


class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///network_analyzer_dev.db'
    SIMULATION_INTERVAL = 10  # More frequent simulation for development
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://user:pass@localhost/network_analyzer'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)


class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_network_analyzer.db'
    SIMULATION_ENABLED = False
    WTF_CSRF_ENABLED = False


# Configuration mapping
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'default')
    return config_map.get(env, DevelopmentConfig)
