"""
Network Traffic Analyzer Web Application
Author: sharondelya
Description: A comprehensive network traffic analyzer with web dashboard featuring
packet capture simulation, protocol parsing, database storage, and elegant visualizations.
"""

import os
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from simple_models import db

def create_app():
    """Application factory pattern for creating Flask app"""
    # Create Flask application
    app = Flask(__name__)
    
    # Configure logging for debugging
    logging.basicConfig(level=logging.DEBUG)
    
    # Set secret key for sessions
    app.secret_key = os.environ.get("SESSION_SECRET", "sharondelya-network-analyzer-secret-key")
    
    # Configure proxy middleware for deployment
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Database configuration
    database_url = os.environ.get("DATABASE_URL", "sqlite:///network_analyzer.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Initialize database with app
    db.init_app(app)
    
    # Register blueprints and routes
    with app.app_context():
        # Import models to ensure tables are created
        
        # Import and register routes - MOVED INSIDE to avoid circular imports
        def register_routes():
            from routes import init_routes
            init_routes(app)
            
        register_routes()
        
        # Create database tables
        db.create_all()
        
        # Database is ready for real data
        print("Database initialized - ready for real packet capture and PCAP file uploads")
        print("Use 'Start Capture' button for live capture or 'Upload PCAP' for trace file analysis")
    
    return app

# Create application instance
app = create_app()

if __name__ == "__main__":
    # Run the application
    app.run(host="0.0.0.0", port=5000, debug=True)