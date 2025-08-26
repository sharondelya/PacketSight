"""
Database Management for Network Traffic Analyzer
Author: sharondelya
Description: Database maintenance and utilities for real network data
"""

from datetime import datetime, timedelta
from sqlalchemy import func
from simple_models import db, Packet, Flow, NetworkStatistics, DNSQuery, HTTPTransaction
import logging

logger = logging.getLogger(__name__)


def cleanup_old_data(days=30):
    """Clean up old data to maintain database performance"""
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Delete old packets
        old_packets = Packet.query.filter(Packet.timestamp < cutoff_date).count()
        if old_packets > 0:
            Packet.query.filter(Packet.timestamp < cutoff_date).delete()
            logger.info(f"Deleted {old_packets} old packets")
        
        # Delete old statistics
        old_stats = NetworkStatistics.query.filter(NetworkStatistics.timestamp < cutoff_date).count()
        if old_stats > 0:
            NetworkStatistics.query.filter(NetworkStatistics.timestamp < cutoff_date).delete()
            logger.info(f"Deleted {old_stats} old statistics")
        
        # Delete old DNS queries
        old_dns = DNSQuery.query.filter(DNSQuery.timestamp < cutoff_date).count()
        if old_dns > 0:
            DNSQuery.query.filter(DNSQuery.timestamp < cutoff_date).delete()
            logger.info(f"Deleted {old_dns} old DNS queries")
        
        # Delete old HTTP transactions
        old_http = HTTPTransaction.query.filter(HTTPTransaction.timestamp < cutoff_date).count()
        if old_http > 0:
            HTTPTransaction.query.filter(HTTPTransaction.timestamp < cutoff_date).delete()
            logger.info(f"Deleted {old_http} old HTTP transactions")
        
        db.session.commit()
        logger.info("Database cleanup completed successfully")
    
    except Exception as e:
        logger.error(f"Error during database cleanup: {e}")
        db.session.rollback()


def get_database_info():
    """Get information about database size and content"""
    try:
        info = {
            'packets': Packet.query.count(),
            'flows': Flow.query.count(),
            'dns_queries': DNSQuery.query.count(),
            'http_transactions': HTTPTransaction.query.count(),
            'statistics': NetworkStatistics.query.count(),
            'oldest_packet': None,
            'newest_packet': None
        }
        
        # Get oldest and newest packet timestamps
        oldest = db.session.query(func.min(Packet.timestamp)).scalar()
        newest = db.session.query(func.max(Packet.timestamp)).scalar()
        
        info['oldest_packet'] = oldest.isoformat() if oldest else None
        info['newest_packet'] = newest.isoformat() if newest else None
        
        return info
    
    except Exception as e:
        logger.error(f"Error getting database info: {e}")
        return {}


def optimize_database():
    """Optimize database performance"""
    try:
        # Add indexes if they don't exist
        from sqlalchemy import text
        
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)",
            "CREATE INDEX IF NOT EXISTS idx_packets_source_ip ON packets(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_packets_dest_ip ON packets(dest_ip)",
            "CREATE INDEX IF NOT EXISTS idx_flows_start_time ON flows(start_time)",
            "CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol)",
            "CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_queries(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_transactions(timestamp)"
        ]
        
        for index_sql in indexes:
            try:
                db.session.execute(text(index_sql))
                logger.info(f"Created index: {index_sql.split()[-1]}")
            except Exception as e:
                logger.warning(f"Index creation skipped: {e}")
        
        db.session.commit()
        logger.info("Database optimization completed")
        
    except Exception as e:
        logger.error(f"Error optimizing database: {e}")
        db.session.rollback()


def get_statistics_summary():
    """Get summary statistics for the dashboard"""
    try:
        # Get recent activity (last 24 hours)
        recent_time = datetime.utcnow() - timedelta(hours=24)
        
        summary = {
            'total_packets': Packet.query.count(),
            'total_flows': Flow.query.count(),
            'active_flows': Flow.query.filter_by(status='ACTIVE').count(),
            'recent_packets': Packet.query.filter(Packet.timestamp >= recent_time).count(),
            'protocols': {},
            'top_sources': [],
            'top_destinations': []
        }
        
        # Protocol distribution
        protocol_stats = db.session.query(
            Packet.protocol,
            func.count(Packet.id).label('count')
        ).group_by(Packet.protocol).all()
        
        for protocol, count in protocol_stats:
            summary['protocols'][protocol] = count
        
        # Top source IPs
        top_sources = db.session.query(
            Packet.source_ip,
            func.count(Packet.id).label('count')
        ).group_by(Packet.source_ip).order_by(func.count(Packet.id).desc()).limit(10).all()
        
        summary['top_sources'] = [{'ip': ip, 'count': count} for ip, count in top_sources]
        
        # Top destination IPs
        top_destinations = db.session.query(
            Packet.dest_ip,
            func.count(Packet.id).label('count')
        ).group_by(Packet.dest_ip).order_by(func.count(Packet.id).desc()).limit(10).all()
        
        summary['top_destinations'] = [{'ip': ip, 'count': count} for ip, count in top_destinations]
        
        return summary
        
    except Exception as e:
        logger.error(f"Error getting statistics summary: {e}")
        return {
            'total_packets': 0,
            'total_flows': 0,
            'active_flows': 0,
            'recent_packets': 0,
            'protocols': {},
            'top_sources': [],
            'top_destinations': []
        }


def vacuum_database():
    """Vacuum database to reclaim space (SQLite specific)"""
    try:
        from sqlalchemy import text
        db.session.execute(text("VACUUM"))
        db.session.commit()
        logger.info("Database vacuum completed")
    except Exception as e:
        logger.error(f"Error during database vacuum: {e}")


def backup_database(backup_path):
    """Create a backup of the database"""
    try:
        import shutil
        import os
        
        # For SQLite databases
        if 'sqlite' in str(db.engine.url):
            db_path = str(db.engine.url).replace('sqlite:///', '')
            if os.path.exists(db_path):
                shutil.copy2(db_path, backup_path)
                logger.info(f"Database backed up to: {backup_path}")
                return True
        
        logger.warning("Backup not implemented for this database type")
        return False
        
    except Exception as e:
        logger.error(f"Error creating database backup: {e}")
        return False