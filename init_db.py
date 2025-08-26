"""
Database Initialization Script for PacketSight
Author: sharondelya
Description: Initialize database tables for network traffic analysis
"""

import os
import sys
import logging
from app import create_app
from simple_models import db, Packet, Flow, NetworkStatistics, DNSQuery, HTTPTransaction

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def init_database(reset=False):
    """Initialize database with tables"""
    app = create_app()
    
    with app.app_context():
        try:
            if reset:
                logger.info("Dropping all existing tables...")
                db.drop_all()
                logger.info("All tables dropped successfully")
            
            logger.info("Creating database tables...")
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Verify tables were created
            tables = [
                ('packets', Packet),
                ('flows', Flow), 
                ('network_statistics', NetworkStatistics),
                ('dns_queries', DNSQuery),
                ('http_transactions', HTTPTransaction)
            ]
            
            logger.info("Verifying database schema...")
            for table_name, model in tables:
                try:
                    count = model.query.count()
                    logger.info(f"✓ Table '{table_name}' created successfully (current records: {count})")
                except Exception as e:
                    logger.error(f"✗ Error with table '{table_name}': {e}")
                    return False
            
            logger.info("Database initialization completed successfully!")
            logger.info("Ready for real packet capture and PCAP file analysis")
            return True
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            return False


def check_database_status():
    """Check current database status"""
    app = create_app()
    
    with app.app_context():
        try:
            logger.info("Database Status Report:")
            logger.info("=" * 50)
            
            # Check each table
            tables = [
                ('Packets', Packet),
                ('Flows', Flow),
                ('Network Statistics', NetworkStatistics), 
                ('DNS Queries', DNSQuery),
                ('HTTP Transactions', HTTPTransaction)
            ]
            
            total_records = 0
            for table_name, model in tables:
                try:
                    count = model.query.count()
                    total_records += count
                    logger.info(f"{table_name:20}: {count:,} records")
                except Exception as e:
                    logger.error(f"{table_name:20}: Error - {e}")
            
            logger.info("=" * 50)
            logger.info(f"Total Records: {total_records:,}")
            
            if total_records == 0:
                logger.info("Database is empty and ready for data collection")
                logger.info("Use 'Start Capture' for live monitoring or 'Upload PCAP' for file analysis")
            else:
                logger.info("Database contains existing data")
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking database status: {e}")
            return False


def cleanup_old_data(days=30):
    """Clean up old data to maintain performance"""
    app = create_app()
    
    with app.app_context():
        try:
            from datetime import datetime, timedelta
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            logger.info(f"Cleaning up data older than {days} days (before {cutoff_date})")
            
            # Clean up each table
            tables = [
                ('Packets', Packet),
                ('Flows', Flow),
                ('Network Statistics', NetworkStatistics),
                ('DNS Queries', DNSQuery), 
                ('HTTP Transactions', HTTPTransaction)
            ]
            
            total_deleted = 0
            for table_name, model in tables:
                try:
                    old_records = model.query.filter(model.timestamp < cutoff_date)
                    count = old_records.count()
                    
                    if count > 0:
                        old_records.delete()
                        total_deleted += count
                        logger.info(f"Deleted {count:,} old records from {table_name}")
                    else:
                        logger.info(f"No old records found in {table_name}")
                        
                except Exception as e:
                    logger.error(f"Error cleaning {table_name}: {e}")
            
            if total_deleted > 0:
                db.session.commit()
                logger.info(f"Successfully deleted {total_deleted:,} old records")
            else:
                logger.info("No old records found to delete")
                
            return True
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            db.session.rollback()
            return False


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PacketSight Database Management")
    parser.add_argument('--reset', action='store_true', 
                       help='Reset database (drop and recreate all tables)')
    parser.add_argument('--status', action='store_true',
                       help='Check database status')
    parser.add_argument('--cleanup', type=int, metavar='DAYS',
                       help='Clean up data older than specified days')
    
    args = parser.parse_args()
    
    if args.status:
        logger.info("Checking database status...")
        success = check_database_status()
        sys.exit(0 if success else 1)
    
    elif args.cleanup:
        logger.info(f"Cleaning up data older than {args.cleanup} days...")
        success = cleanup_old_data(args.cleanup)
        sys.exit(0 if success else 1)
    
    else:
        logger.info("Initializing PacketSight database...")
        success = init_database(reset=args.reset)
        
        if success:
            logger.info("Database initialization completed successfully!")
            logger.info("You can now start the application with: python app.py")
        else:
            logger.error("Database initialization failed!")
            sys.exit(1)