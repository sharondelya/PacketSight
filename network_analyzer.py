"""
Network Traffic Analyzer Core Engine
Author: sharondelya
Description: Core analysis engine for processing network traffic data and generating insights
"""

from datetime import datetime, timedelta
from sqlalchemy import func, desc, and_, or_
from simple_models import Packet, Flow, NetworkStatistics, DNSQuery, HTTPTransaction
from simple_models import db
import logging

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """Core network analysis engine"""
    
    def __init__(self):
        self.alert_thresholds = {
            'packets_per_second': 1000,
            'bytes_per_second': 10485760,  # 10 MB
            'failed_connections': 50,
            'suspicious_ports': [23, 135, 139, 445, 1433, 3389, 5900]
        }
    
    def get_traffic_trends(self, hours=24):
        """Analyze traffic trends over specified time period"""
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            # Group traffic by hour
            results = db.session.query(
                func.date_trunc('hour', Packet.timestamp).label('hour'),
                func.count(Packet.id).label('packet_count'),
                func.sum(Packet.packet_size).label('total_bytes'),
                func.avg(Packet.packet_size).label('avg_packet_size')
            ).filter(
                Packet.timestamp >= time_threshold
            ).group_by('hour').order_by('hour').all()
            
            trends = []
            for result in results:
                trends.append({
                    'timestamp': result.hour.isoformat() if result.hour else '',
                    'packet_count': result.packet_count or 0,
                    'total_bytes': result.total_bytes or 0,
                    'avg_packet_size': round(result.avg_packet_size or 0, 2),
                    'mbps': round((result.total_bytes or 0) * 8 / 1048576 / 3600, 2)  # Convert to Mbps
                })
            
            return trends
        
        except Exception as e:
            logger.error(f"Error analyzing traffic trends: {e}")
            return []
    
    def get_protocol_analysis(self, hours=24):
        """Analyze protocol distribution and characteristics"""
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            # Protocol statistics
            protocol_stats = db.session.query(
                Packet.protocol,
                func.count(Packet.id).label('packet_count'),
                func.sum(Packet.packet_size).label('total_bytes'),
                func.avg(Packet.packet_size).label('avg_packet_size'),
                func.min(Packet.packet_size).label('min_packet_size'),
                func.max(Packet.packet_size).label('max_packet_size')
            ).filter(
                Packet.timestamp >= time_threshold
            ).group_by(Packet.protocol).order_by(desc('packet_count')).all()
            
            analysis = []
            total_packets = sum(stat.packet_count for stat in protocol_stats)
            total_bytes = sum(stat.total_bytes or 0 for stat in protocol_stats)
            
            for stat in protocol_stats:
                packet_percentage = (stat.packet_count / total_packets * 100) if total_packets > 0 else 0
                byte_percentage = ((stat.total_bytes or 0) / total_bytes * 100) if total_bytes > 0 else 0
                
                analysis.append({
                    'protocol': stat.protocol,
                    'packet_count': stat.packet_count,
                    'total_bytes': stat.total_bytes or 0,
                    'packet_percentage': round(packet_percentage, 2),
                    'byte_percentage': round(byte_percentage, 2),
                    'avg_packet_size': round(stat.avg_packet_size or 0, 2),
                    'min_packet_size': stat.min_packet_size or 0,
                    'max_packet_size': stat.max_packet_size or 0
                })
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error analyzing protocols: {e}")
            return []
    
    def get_top_endpoints(self, limit=20, hours=24):
        """Get top talking endpoints (IP addresses)"""
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            # Top source IPs
            top_sources = db.session.query(
                Packet.source_ip,
                func.count(Packet.id).label('packet_count'),
                func.sum(Packet.packet_size).label('total_bytes'),
                func.count(func.distinct(Packet.dest_ip)).label('unique_destinations')
            ).filter(
                Packet.timestamp >= time_threshold
            ).group_by(Packet.source_ip)\
             .order_by(desc('packet_count'))\
             .limit(limit).all()
            
            # Top destination IPs
            top_destinations = db.session.query(
                Packet.dest_ip,
                func.count(Packet.id).label('packet_count'),
                func.sum(Packet.packet_size).label('total_bytes'),
                func.count(func.distinct(Packet.source_ip)).label('unique_sources')
            ).filter(
                Packet.timestamp >= time_threshold
            ).group_by(Packet.dest_ip)\
             .order_by(desc('packet_count'))\
             .limit(limit).all()
            
            endpoints = {
                'top_sources': [{
                    'ip': src.source_ip,
                    'packet_count': src.packet_count,
                    'total_bytes': src.total_bytes or 0,
                    'unique_destinations': src.unique_destinations,
                    'type': 'internal' if self._is_internal_ip(src.source_ip) else 'external'
                } for src in top_sources],
                
                'top_destinations': [{
                    'ip': dst.dest_ip,
                    'packet_count': dst.packet_count,
                    'total_bytes': dst.total_bytes or 0,
                    'unique_sources': dst.unique_sources,
                    'type': 'internal' if self._is_internal_ip(dst.dest_ip) else 'external'
                } for dst in top_destinations]
            }
            
            return endpoints
        
        except Exception as e:
            logger.error(f"Error analyzing endpoints: {e}")
            return {'top_sources': [], 'top_destinations': []}
    
    def get_security_indicators(self, hours=24):
        """Analyze security-related indicators and potential threats"""
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            alerts = []
            
            # 1. Port scan detection - many unique ports from single source
            port_scan_results = db.session.query(
                Packet.source_ip,
                func.count(func.distinct(Packet.dest_port)).label('unique_ports'),
                func.count(Packet.id).label('packet_count')
            ).filter(
                and_(
                    Packet.timestamp >= time_threshold,
                    Packet.dest_port.isnot(None)
                )
            ).group_by(Packet.source_ip)\
             .having(func.count(func.distinct(Packet.dest_port)) > 20)\
             .order_by(desc('unique_ports')).all()
            
            for result in port_scan_results:
                alerts.append({
                    'type': 'Port Scan Detected',
                    'severity': 'HIGH',
                    'source_ip': result.source_ip,
                    'description': f'IP scanned {result.unique_ports} unique ports',
                    'packet_count': result.packet_count,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            # 2. Suspicious port activity
            suspicious_ports = db.session.query(
                Packet.dest_port,
                Packet.source_ip,
                func.count(Packet.id).label('attempts')
            ).filter(
                and_(
                    Packet.timestamp >= time_threshold,
                    Packet.dest_port.in_(self.alert_thresholds['suspicious_ports'])
                )
            ).group_by(Packet.dest_port, Packet.source_ip)\
             .having(func.count(Packet.id) > 5).all()
            
            for result in suspicious_ports:
                alerts.append({
                    'type': 'Suspicious Port Activity',
                    'severity': 'MEDIUM',
                    'source_ip': result.source_ip,
                    'description': f'{result.attempts} attempts to port {result.dest_port}',
                    'port': result.dest_port,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            # 3. High traffic volume from single source
            high_volume = db.session.query(
                Packet.source_ip,
                func.count(Packet.id).label('packet_count'),
                func.sum(Packet.packet_size).label('total_bytes')
            ).filter(
                Packet.timestamp >= time_threshold
            ).group_by(Packet.source_ip)\
             .having(func.count(Packet.id) > 1000)\
             .order_by(desc('packet_count')).all()
            
            for result in high_volume:
                mbytes = (result.total_bytes or 0) / 1048576
                alerts.append({
                    'type': 'High Volume Traffic',
                    'severity': 'MEDIUM',
                    'source_ip': result.source_ip,
                    'description': f'{result.packet_count} packets ({mbytes:.1f} MB)',
                    'packet_count': result.packet_count,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            # 4. Failed DNS queries (potential DNS tunneling or DGA)
            failed_dns = db.session.query(
                DNSQuery.source_ip,
                func.count(DNSQuery.id).label('failed_queries')
            ).filter(
                and_(
                    DNSQuery.timestamp >= time_threshold,
                    DNSQuery.response_code != 0
                )
            ).group_by(DNSQuery.source_ip)\
             .having(func.count(DNSQuery.id) > 10).all()
            
            for result in failed_dns:
                alerts.append({
                    'type': 'High DNS Failure Rate',
                    'severity': 'LOW',
                    'source_ip': result.source_ip,
                    'description': f'{result.failed_queries} failed DNS queries',
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            # 5. Unusual protocol distribution
            total_packets = Packet.query.filter(Packet.timestamp >= time_threshold).count()
            if total_packets > 0:
                icmp_count = Packet.query.filter(
                    and_(
                        Packet.timestamp >= time_threshold,
                        Packet.protocol == 'ICMP'
                    )
                ).count()
                
                icmp_percentage = (icmp_count / total_packets) * 100
                if icmp_percentage > 10:  # More than 10% ICMP is unusual
                    alerts.append({
                        'type': 'Unusual ICMP Activity',
                        'severity': 'LOW',
                        'description': f'ICMP traffic is {icmp_percentage:.1f}% of total traffic',
                        'percentage': round(icmp_percentage, 1),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            return alerts
        
        except Exception as e:
            logger.error(f"Error analyzing security indicators: {e}")
            return []
    
    def get_flow_analysis(self, hours=24, status=None):
        """Analyze network flows for patterns and anomalies"""
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            query = Flow.query.filter(Flow.start_time >= time_threshold)
            
            if status:
                query = query.filter(Flow.status == status)
            
            flows = query.all()
            
            analysis = {
                'total_flows': len(flows),
                'active_flows': len([f for f in flows if f.status == 'ACTIVE']),
                'closed_flows': len([f for f in flows if f.status == 'CLOSED']),
                'timeout_flows': len([f for f in flows if f.status == 'TIMEOUT']),
                'avg_duration': 0,
                'avg_packets_per_flow': 0,
                'avg_bytes_per_flow': 0,
                'protocol_distribution': {},
                'long_duration_flows': [],
                'high_volume_flows': []
            }
            
            if flows:
                # Calculate averages
                total_duration = sum(f.duration or 0 for f in flows)
                total_packets = sum(f.packet_count or 0 for f in flows)
                total_bytes = sum(f.total_bytes or 0 for f in flows)
                
                analysis['avg_duration'] = round(total_duration / len(flows), 2)
                analysis['avg_packets_per_flow'] = round(total_packets / len(flows), 2)
                analysis['avg_bytes_per_flow'] = round(total_bytes / len(flows), 2)
                
                # Protocol distribution
                protocol_count = {}
                for flow in flows:
                    protocol_count[flow.protocol] = protocol_count.get(flow.protocol, 0) + 1
                analysis['protocol_distribution'] = protocol_count
                
                # Long duration flows (> 1 hour)
                long_flows = [f for f in flows if f.duration and f.duration > 3600]
                analysis['long_duration_flows'] = [{
                    'flow_id': f.flow_id,
                    'source_ip': f.source_ip,
                    'dest_ip': f.dest_ip,
                    'duration': f.duration,
                    'protocol': f.protocol
                } for f in long_flows[:10]]
                
                # High volume flows (> 1 MB)
                high_volume = [f for f in flows if f.total_bytes and f.total_bytes > 1048576]
                analysis['high_volume_flows'] = [{
                    'flow_id': f.flow_id,
                    'source_ip': f.source_ip,
                    'dest_ip': f.dest_ip,
                    'total_bytes': f.total_bytes,
                    'protocol': f.protocol
                } for f in high_volume[:10]]
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error analyzing flows: {e}")
            return {}
    
    def get_dns_analysis(self, hours=24):
        """Analyze DNS traffic patterns"""
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            # DNS query statistics
            dns_queries = db.session.query(
                func.count(DNSQuery.id).label('total_queries'),
                func.count(func.distinct(DNSQuery.query_name)).label('unique_domains'),
                func.avg(DNSQuery.response_time).label('avg_response_time'),
                func.sum(func.case([(DNSQuery.response_code == 0, 1)], else_=0)).label('successful_queries'),
                func.sum(func.case([(DNSQuery.is_cached == True, 1)], else_=0)).label('cached_queries')
            ).filter(DNSQuery.timestamp >= time_threshold).first()
            
            # Top queried domains
            top_domains = db.session.query(
                DNSQuery.query_name,
                func.count(DNSQuery.id).label('query_count'),
                func.avg(DNSQuery.response_time).label('avg_response_time')
            ).filter(
                DNSQuery.timestamp >= time_threshold
            ).group_by(DNSQuery.query_name)\
             .order_by(desc('query_count'))\
             .limit(20).all()
            
            # Query type distribution
            query_types = db.session.query(
                DNSQuery.query_type,
                func.count(DNSQuery.id).label('count')
            ).filter(
                DNSQuery.timestamp >= time_threshold
            ).group_by(DNSQuery.query_type).all()
            
            analysis = {
                'total_queries': dns_queries.total_queries or 0,
                'unique_domains': dns_queries.unique_domains or 0,
                'avg_response_time': round(dns_queries.avg_response_time or 0, 2),
                'success_rate': round((dns_queries.successful_queries or 0) / (dns_queries.total_queries or 1) * 100, 2),
                'cache_hit_rate': round((dns_queries.cached_queries or 0) / (dns_queries.total_queries or 1) * 100, 2),
                'top_domains': [{
                    'domain': domain.query_name,
                    'query_count': domain.query_count,
                    'avg_response_time': round(domain.avg_response_time or 0, 2)
                } for domain in top_domains],
                'query_type_distribution': {qt.query_type: qt.count for qt in query_types}
            }
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error analyzing DNS traffic: {e}")
            return {}
    
    def _is_internal_ip(self, ip_address):
        """Check if IP address is in private/internal range"""
        if not ip_address:
            return False
        
        # Simple check for common internal IP ranges
        return (ip_address.startswith('192.168.') or 
                ip_address.startswith('10.') or
                ip_address.startswith('172.16.') or
                ip_address.startswith('172.17.') or
                ip_address.startswith('172.18.') or
                ip_address.startswith('172.19.') or
                ip_address.startswith('172.20.') or
                ip_address.startswith('172.21.') or
                ip_address.startswith('172.22.') or
                ip_address.startswith('172.23.') or
                ip_address.startswith('172.24.') or
                ip_address.startswith('172.25.') or
                ip_address.startswith('172.26.') or
                ip_address.startswith('172.27.') or
                ip_address.startswith('172.28.') or
                ip_address.startswith('172.29.') or
                ip_address.startswith('172.30.') or
                ip_address.startswith('172.31.'))
    
    def update_statistics(self):
        """Update network statistics for dashboard metrics"""
        try:
            current_time = datetime.utcnow()
            
            # Traffic volume statistics (last hour)
            hour_ago = current_time - timedelta(hours=1)
            hourly_stats = db.session.query(
                func.count(Packet.id).label('packet_count'),
                func.sum(Packet.packet_size).label('total_bytes')
            ).filter(Packet.timestamp >= hour_ago).first()
            
            # Save traffic statistics
            if hourly_stats and hourly_stats.packet_count:
                traffic_stat = NetworkStatistics(
                    timestamp=current_time,
                    metric_name='packets_per_hour',
                    metric_value=hourly_stats.packet_count,
                    metric_unit='packets',
                    category='TRAFFIC'
                )
                db.session.add(traffic_stat)
                
                bytes_stat = NetworkStatistics(
                    timestamp=current_time,
                    metric_name='bytes_per_hour',
                    metric_value=hourly_stats.total_bytes or 0,
                    metric_unit='bytes',
                    category='TRAFFIC'
                )
                db.session.add(bytes_stat)
            
            # Protocol statistics
            protocols = db.session.query(
                Packet.protocol,
                func.count(Packet.id).label('count')
            ).filter(
                Packet.timestamp >= hour_ago
            ).group_by(Packet.protocol).all()
            
            for protocol_stat in protocols:
                stat = NetworkStatistics(
                    timestamp=current_time,
                    metric_name=f'packets_{protocol_stat.protocol.lower()}',
                    metric_value=protocol_stat.count,
                    metric_unit='packets',
                    category='PROTOCOL',
                    protocol=protocol_stat.protocol
                )
                db.session.add(stat)
            
            db.session.commit()
            logger.info("Network statistics updated successfully")
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
            db.session.rollback()
