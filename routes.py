"""
Routes for Network Traffic Analyzer Web Application
Author: sharondelya
Description: Flask routes handling web requests and API endpoints
"""

import json
import random
import os
from datetime import datetime, timedelta
from flask import render_template, request, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename
from sqlalchemy import func, desc, and_

from network_analyzer import NetworkAnalyzer
from real_packet_capture import get_capture_instance
from pcap_parser import PCAPParser, validate_pcap_file
import logging

logger = logging.getLogger(__name__)


def get_time_delta(time_range):
    """Helper function to parse time range strings"""
    if time_range == 'all':
        return None
    
    if time_range.endswith('h'):
        hours = int(time_range[:-1])
        return timedelta(hours=hours)
    elif time_range.endswith('d'):
        days = int(time_range[:-1])
        return timedelta(days=days)
    else:
        return timedelta(hours=24)  # Default to 24 hours

def init_routes(app):
    """Initialize all routes for the Flask application"""
    
    # Import models inside the function to avoid circular imports
    from simple_models import db, Packet, Flow, NetworkStatistics, DNSQuery, HTTPTransaction
    
    @app.route('/')
    def index():
        """Main dashboard route"""
        return redirect(url_for('dashboard'))
    
    @app.route('/dashboard')
    def dashboard():
        """Network traffic dashboard with real-time statistics"""
        try:
            # Get recent statistics for dashboard
            analyzer = NetworkAnalyzer()
            
            # Get total counts
            total_packets = Packet.query.count()
            total_flows = Flow.query.count()
            active_flows = Flow.query.filter_by(status='ACTIVE').count()
            
            # Get protocol distribution
            protocol_stats = db.session.query(
                Packet.protocol, 
                func.count(Packet.id).label('count')
            ).group_by(Packet.protocol).all()
            
            # Get recent activity (last 24 hours)
            recent_time = datetime.utcnow() - timedelta(hours=24)
            recent_packets = Packet.query.filter(
                Packet.timestamp >= recent_time
            ).count()
            
            # Get top talkers (most active IPs)
            top_sources = db.session.query(
                Packet.source_ip,
                func.count(Packet.id).label('packet_count'),
                func.sum(Packet.packet_size).label('total_bytes')
            ).group_by(Packet.source_ip)\
             .order_by(desc('packet_count'))\
             .limit(10).all()
            
            return render_template('dashboard.html',
                                 total_packets=total_packets,
                                 total_flows=total_flows,
                                 active_flows=active_flows,
                                 recent_packets=recent_packets,
                                 protocol_stats=protocol_stats,
                                 top_sources=top_sources)
        
        except Exception as e:
            logger.error(f"Dashboard error: {str(e)}")
            return render_template('dashboard.html',
                                 total_packets=0,
                                 total_flows=0,
                                 active_flows=0,
                                 recent_packets=0,
                                 protocol_stats=[],
                                 top_sources=[])
    
    @app.route('/packets')
    def packets():
        """Display packet capture data with filtering"""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = 50
            
            # Build query with filters
            query = Packet.query
            
            # Protocol filter
            protocol = request.args.get('protocol')
            if protocol and protocol != 'all':
                query = query.filter(Packet.protocol == protocol)
            
            # IP address filter
            ip_filter = request.args.get('ip')
            if ip_filter:
                query = query.filter(
                    (Packet.source_ip.like(f'%{ip_filter}%')) |
                    (Packet.dest_ip.like(f'%{ip_filter}%'))
                )
            
            # Time range filter
            time_range = request.args.get('time_range', '1h')
            if time_range:
                time_delta = get_time_delta(time_range)
                if time_delta:
                    query = query.filter(
                        Packet.timestamp >= datetime.utcnow() - time_delta
                    )
            
            # Order by timestamp descending
            query = query.order_by(desc(Packet.timestamp))
            
            # Paginate results
            packets = query.paginate(
                page=page, per_page=per_page, error_out=False
            )
            
            # Get available protocols for filter dropdown
            protocols = db.session.query(Packet.protocol.distinct()).all()
            protocols = [p[0] for p in protocols]
            
            return render_template('packets.html',
                                 packets=packets,
                                 protocols=protocols,
                                 current_protocol=protocol,
                                 current_ip=ip_filter,
                                 current_time_range=time_range)
        
        except Exception as e:
            logger.error(f"Packets view error: {str(e)}")
            return render_template('packets.html',
                                 packets=None,
                                 protocols=[],
                                 current_protocol=None,
                                 current_ip=None,
                                 current_time_range='1h')
    
    @app.route('/flows')
    def flows():
        """Display network flows with analysis"""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = 25
            
            # Build query with filters
            query = Flow.query
            
            # Status filter
            status = request.args.get('status')
            if status and status != 'all':
                query = query.filter(Flow.status == status)
            
            # Protocol filter
            protocol = request.args.get('protocol')
            if protocol and protocol != 'all':
                query = query.filter(Flow.protocol == protocol)
            
            # Order by start time descending
            query = query.order_by(desc(Flow.start_time))
            
            # Paginate results
            flows = query.paginate(
                page=page, per_page=per_page, error_out=False
            )
            
            # Get filter options
            statuses = db.session.query(Flow.status.distinct()).all()
            statuses = [s[0] for s in statuses if s[0]]
            
            protocols = db.session.query(Flow.protocol.distinct()).all()
            protocols = [p[0] for p in protocols]
            
            return render_template('flows.html',
                                 flows=flows,
                                 statuses=statuses,
                                 protocols=protocols,
                                 current_status=status,
                                 current_protocol=protocol)
        
        except Exception as e:
            logger.error(f"Flows view error: {str(e)}")
            return render_template('flows.html',
                                 flows=[],
                                 statuses=[],
                                 protocols=[],
                                 current_status=None,
                                 current_protocol=None)
    
    @app.route('/analytics')
    def analytics():
        """Advanced analytics and visualizations"""
        try:
            analyzer = NetworkAnalyzer()
            
            # Get comprehensive analytics
            traffic_trends = analyzer.get_traffic_trends(hours=24)
            protocol_analysis = analyzer.get_protocol_analysis()
            top_endpoints = analyzer.get_top_endpoints(limit=20)
            security_alerts = analyzer.get_security_indicators()
            
            return render_template('analytics.html',
                                 traffic_trends=traffic_trends,
                                 protocol_analysis=protocol_analysis,
                                 top_endpoints=top_endpoints,
                                 security_alerts=security_alerts)
        
        except Exception as e:
            logger.error(f"Analytics view error: {str(e)}")
            return render_template('analytics.html',
                                 traffic_trends=[],
                                 protocol_analysis=[],
                                 top_endpoints=[],
                                 security_alerts=[])
    
    # API Routes for real-time data
    @app.route('/api/stats')
    def api_stats():
        """API endpoint for real-time statistics"""
        try:
            # Get current statistics
            total_packets = Packet.query.count()
            total_flows = Flow.query.count()
            active_flows = Flow.query.filter_by(status='ACTIVE').count()
            
            # Get recent activity (last hour)
            recent_time = datetime.utcnow() - timedelta(hours=1)
            recent_packets = Packet.query.filter(
                Packet.timestamp >= recent_time
            ).count()
            
            return jsonify({
                'total_packets': total_packets,
                'total_flows': total_flows,
                'active_flows': active_flows,
                'recent_packets': recent_packets,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        except Exception as e:
            logger.error(f"API stats error: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/protocol-distribution')
    def api_protocol_distribution():
        """API endpoint for protocol distribution data"""
        try:
            # Get protocol distribution
            results = db.session.query(
                Packet.protocol,
                func.count(Packet.id).label('count'),
                func.sum(Packet.packet_size).label('bytes')
            ).group_by(Packet.protocol).all()
            
            data = [{
                'protocol': result.protocol,
                'count': result.count,
                'bytes': result.bytes or 0
            } for result in results]
            
            return jsonify(data)
        
        except Exception as e:
            logger.error(f"API protocol distribution error: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/traffic-timeline')
    def api_traffic_timeline():
        """API endpoint for traffic timeline data"""
        try:
            hours = request.args.get('hours', 24, type=int)
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            # For SQLite, use strftime instead of date_trunc
            results = db.session.query(
                func.strftime('%Y-%m-%d %H:00:00', Packet.timestamp).label('hour'),
                func.count(Packet.id).label('packets'),
                func.sum(Packet.packet_size).label('bytes')
            ).filter(
                Packet.timestamp >= time_threshold
            ).group_by(func.strftime('%Y-%m-%d %H:00:00', Packet.timestamp))\
             .order_by(func.strftime('%Y-%m-%d %H:00:00', Packet.timestamp)).all()
            
            data = []
            for result in results:
                try:
                    # Parse the hour string back to datetime for ISO format
                    hour_dt = datetime.strptime(result.hour, '%Y-%m-%d %H:%M:%S')
                    data.append({
                        'timestamp': hour_dt.isoformat(),
                        'packets': result.packets,
                        'bytes': result.bytes or 0
                    })
                except:
                    # Fallback if parsing fails
                    data.append({
                        'timestamp': result.hour,
                        'packets': result.packets,
                        'bytes': result.bytes or 0
                    })
            
            return jsonify(data)
        
        except Exception as e:
            logger.error(f"API traffic timeline error: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/top-talkers')
    def api_top_talkers():
        """API endpoint for top talking hosts"""
        try:
            limit = request.args.get('limit', 10, type=int)
            
            # Get top source IPs by packet count
            results = db.session.query(
                Packet.source_ip,
                func.count(Packet.id).label('packets'),
                func.sum(Packet.packet_size).label('bytes')
            ).group_by(Packet.source_ip)\
             .order_by(desc('packets'))\
             .limit(limit).all()
            
            data = [{
                'ip': result.source_ip,
                'packets': result.packets,
                'bytes': result.bytes or 0
            } for result in results]
            
            return jsonify(data)
        
        except Exception as e:
            logger.error(f"API top talkers error: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/recent-activity')
    def api_recent_activity():
        """API endpoint for recent network activity"""
        try:
            limit = request.args.get('limit', 10, type=int)
            
            # Get recent packets with activity details
            recent_packets = Packet.query.order_by(desc(Packet.timestamp)).limit(limit).all()
            
            activities = []
            for packet in recent_packets:
                # Determine activity type and details based on protocol
                if packet.protocol == 'HTTP':
                    activity_type = 'http'
                    icon = 'fas fa-globe'
                    color = 'primary'
                    title = f"HTTP Request to {packet.dest_ip}"
                    details = f"Port {packet.dest_port} - {packet.packet_size} bytes"
                elif packet.protocol == 'HTTPS':
                    activity_type = 'https'
                    icon = 'fas fa-lock'
                    color = 'success'
                    title = f"HTTPS Request to {packet.dest_ip}"
                    details = f"Port {packet.dest_port} - {packet.packet_size} bytes"
                elif packet.protocol == 'DNS':
                    activity_type = 'dns'
                    icon = 'fas fa-search'
                    color = 'info'
                    title = f"DNS Query from {packet.source_ip}"
                    details = f"Port {packet.dest_port} - {packet.packet_size} bytes"
                elif packet.protocol == 'TCP':
                    activity_type = 'tcp'
                    icon = 'fas fa-exchange-alt'
                    color = 'secondary'
                    title = f"TCP Connection {packet.source_ip} → {packet.dest_ip}"
                    details = f"Port {packet.dest_port} - {packet.packet_size} bytes"
                elif packet.protocol == 'UDP':
                    activity_type = 'udp'
                    icon = 'fas fa-paper-plane'
                    color = 'warning'
                    title = f"UDP Packet {packet.source_ip} → {packet.dest_ip}"
                    details = f"Port {packet.dest_port} - {packet.packet_size} bytes"
                else:
                    activity_type = 'other'
                    icon = 'fas fa-network-wired'
                    color = 'dark'
                    title = f"{packet.protocol} Traffic"
                    details = f"{packet.source_ip} → {packet.dest_ip}"
                
                # Calculate time ago
                time_diff = datetime.utcnow() - packet.timestamp
                if time_diff.seconds < 60:
                    time_ago = f"{time_diff.seconds}s ago"
                elif time_diff.seconds < 3600:
                    time_ago = f"{time_diff.seconds // 60}m ago"
                else:
                    time_ago = f"{time_diff.seconds // 3600}h ago"
                
                activities.append({
                    'type': activity_type,
                    'icon': icon,
                    'color': color,
                    'title': title,
                    'details': details,
                    'time_ago': time_ago,
                    'timestamp': packet.timestamp.isoformat()
                })
            
            return jsonify(activities)
        
        except Exception as e:
            logger.error(f"API recent activity error: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/capture-status')
    def capture_status():
        """Get current packet capture status"""
        try:
            capture_instance = get_capture_instance(app)
            status = capture_instance.get_status()
            return jsonify(status)
        except Exception as e:
            logger.error(f"Error getting capture status: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/capture-progress')
    def api_capture_progress():
        """API endpoint for capture progress updates"""
        try:
            capture_instance = get_capture_instance(app)
            status = capture_instance.get_status()
            
            # Get recent packet count for rate calculation
            recent_time = datetime.utcnow() - timedelta(minutes=1)
            recent_packets = Packet.query.filter(
                Packet.timestamp >= recent_time
            ).count()
            
            # Calculate packets per second (approximate)
            packets_per_second = recent_packets / 60 if recent_packets > 0 else 0
            
            # Get total captured packets
            total_packets = Packet.query.count()
            
            return jsonify({
                'active': status.get('active', False),
                'packet_count': total_packets,
                'packets_per_second': round(packets_per_second, 1),
                'interface': status.get('interface', 'Unknown'),
                'duration': status.get('duration', 0),
                'error': status.get('error', None)
            })
            
        except Exception as e:
            logger.error(f"API capture progress error: {str(e)}")
            return jsonify({
                'active': False,
                'packet_count': 0,
                'packets_per_second': 0,
                'interface': 'Unknown',
                'duration': 0,
                'error': str(e)
            }), 500
    
    @app.route('/network-interfaces')
    def network_interfaces():
        """Get available network interfaces"""
        try:
            # Return basic interface information
            interfaces = [
                {'name': 'auto', 'description': 'Auto-detect interface'},
                {'name': 'eth0', 'description': 'Ethernet interface'},
                {'name': 'wlan0', 'description': 'Wireless interface'}
            ]
            return jsonify(interfaces)
        except Exception as e:
            logger.error(f"Error getting network interfaces: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/port-analysis')
    def api_port_analysis():
        """API endpoint for port analysis data"""
        try:
            # Get port activity from database
            results = db.session.query(
                Packet.dest_port,
                func.count(Packet.id).label('connections'),
                func.sum(Packet.packet_size).label('volume')
            ).group_by(Packet.dest_port).order_by(desc('connections')).limit(15).all()
            
            port_services = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 25: 'SMTP', 53: 'DNS',
                21: 'FTP', 23: 'Telnet', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS',
                995: 'POP3S', 587: 'SMTP', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis'
            }
            
            data = []
            for result in results:
                port = result.dest_port
                service = port_services.get(port, 'Unknown')
                volume_mb = (result.volume or 0) / (1024 * 1024)
                
                data.append({
                    'port': port,
                    'service': service,
                    'connections': result.connections,
                    'volume': f'{volume_mb:.1f} MB'
                })
            
            return jsonify(data)
        
        except Exception as e:
            logger.error(f"API port analysis error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/geo-analysis')  
    def api_geo_analysis():
        """API endpoint for geographic analysis data"""
        try:
            # Analyze source IPs for geographic distribution
            results = db.session.query(
                Packet.source_ip,
                func.count(Packet.id).label('connections')
            ).group_by(Packet.source_ip).order_by(desc('connections')).limit(20).all()
            
            # Map IP ranges to countries (simplified for demo)
            geo_mapping = {
                '192.168': {'country': 'Local Network', 'region': 'Internal', 'risk': 'Low'},
                '10.': {'country': 'Private Network', 'region': 'Internal', 'risk': 'Low'}, 
                '172.': {'country': 'Private Network', 'region': 'Internal', 'risk': 'Low'},
                '74.': {'country': 'United States', 'region': 'North America', 'risk': 'Low'},
                '8.8': {'country': 'United States', 'region': 'North America', 'risk': 'Low'},
                '1.1': {'country': 'United States', 'region': 'North America', 'risk': 'Low'},
                '185.': {'country': 'Germany', 'region': 'Europe', 'risk': 'Low'},
                '91.': {'country': 'United Kingdom', 'region': 'Europe', 'risk': 'Low'},
                '114.': {'country': 'China', 'region': 'Asia', 'risk': 'Medium'},
                '46.': {'country': 'Russia', 'region': 'Europe/Asia', 'risk': 'High'}
            }
            
            country_stats = {}
            for result in results:
                ip = result.source_ip
                prefix = ip.split('.')[0] + '.' if '.' in ip else ip[:3]
                
                geo_info = geo_mapping.get(prefix, {
                    'country': 'Unknown', 
                    'region': 'Unknown',  
                    'risk': 'Medium'
                })
                
                country = geo_info['country']
                if country not in country_stats:
                    country_stats[country] = {
                        'country': country,
                        'region': geo_info['region'],
                        'connections': 0,
                        'risk': geo_info['risk']
                    }
                country_stats[country]['connections'] += result.connections
            
            data = list(country_stats.values())
            data.sort(key=lambda x: x['connections'], reverse=True)
            
            return jsonify(data[:12])
        
        except Exception as e:
            logger.error(f"API geo analysis error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/simulate-traffic', methods=['POST'])
    def simulate_traffic():
        """Simulate additional network traffic for testing"""
        try:
            from packet_simulator import PacketSimulator
            
            # Get parameters from request
            data = request.get_json() or {}
            packet_count = data.get('packet_count', 100)
            protocols = data.get('protocols', ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'])
            
            logger.info(f"API Traffic simulation triggered - generating {packet_count} packets")
            
            # Generate traffic
            simulator = PacketSimulator()
            generated_packets = simulator.generate_traffic_batch(packet_count, protocols)
            
            # Also generate some flows
            for _ in range(5):
                simulator.generate_realistic_flow(
                    protocol=random.choice(['TCP', 'HTTP', 'HTTPS']),
                    duration_minutes=random.randint(1, 10)
                )
            
            return jsonify({
                'success': True,
                'message': f'Generated {generated_packets} packets successfully',
                'generated_packets': generated_packets
            })
        except Exception as e:
            logger.error(f"Error simulating traffic: {e}")
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/simulate-traffic', methods=['POST'])
    def simulate_traffic_base():
        """Simulate traffic endpoint for base template"""
        try:
            from packet_simulator import PacketSimulator
            
            logger.info("Traffic simulation triggered from base template")
            
            # Generate traffic
            simulator = PacketSimulator()
            generated_packets = simulator.generate_traffic_batch(100, ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'])
            
            # Also generate some flows
            for _ in range(3):
                simulator.generate_realistic_flow(
                    protocol=random.choice(['TCP', 'HTTP', 'HTTPS']),
                    duration_minutes=random.randint(1, 10)
                )
            
            return jsonify({
                'success': True,
                'message': f'Generated {generated_packets} packets successfully',
                'generated_packets': generated_packets
            })
        except Exception as e:
            logger.error(f"Error simulating traffic: {e}")
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/api/start-capture', methods=['POST'])
    def start_capture():
        """Start packet capture"""
        try:
            capture_instance = get_capture_instance(app)
            success, message = capture_instance.start_capture()
            
            return jsonify({
                'success': success,
                'message': message
            })
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/api/stop-capture', methods=['POST'])
    def stop_capture():
        """Stop packet capture"""
        try:
            capture_instance = get_capture_instance(app)
            success, message = capture_instance.stop_capture()
            
            return jsonify({
                'success': success,
                'message': message
            })
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/upload')
    def upload_page():
        """PCAP file upload page"""
        return render_template('upload.html')
    
    @app.route('/documentation')
    def documentation():
        """Project documentation page"""
        return render_template('documentation.html')

    @app.route('/api/upload-pcap', methods=['POST'])
    def upload_pcap():
        """Upload and parse PCAP file"""
        try:
            if 'file' not in request.files:
                return jsonify({'success': False, 'message': 'No file selected'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'message': 'No file selected'}), 400
            
            # Validate file extension
            allowed_extensions = {'.pcap', '.pcapng', '.cap'}
            file_ext = os.path.splitext(file.filename)[1].lower()
            
            if file_ext not in allowed_extensions:
                return jsonify({
                    'success': False, 
                    'message': f'Invalid file format. Supported formats: {", ".join(allowed_extensions)}'
                }), 400
            
            # Create uploads directory if it doesn't exist
            upload_dir = os.path.join(app.instance_path, 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            file_path = os.path.join(upload_dir, filename)
            
            file.save(file_path)
            logger.info(f"Uploaded PCAP file saved: {file_path}")
            
            # Get file info first
            parser = PCAPParser()
            file_info = parser.get_file_info(file_path)
            
            # Parse with limit for large files
            max_packets = request.form.get('max_packets', type=int)
            if not max_packets or max_packets > 10000:
                max_packets = 10000  # Limit to prevent memory issues
            
            # Parse the file with proper error handling
            logger.info(f"Starting to parse PCAP file: {filename}")
            try:
                parse_results = parser.parse_file(file_path, max_packets=max_packets)
            except Exception as parse_error:
                # Handle database constraint errors specifically
                if 'UNIQUE constraint failed' in str(parse_error):
                    logger.warning(f"Duplicate data detected in PCAP file: {filename}. Some packets/flows may already exist in the database.")
                    # Clean up uploaded file
                    try:
                        os.remove(file_path)
                        logger.info(f"Cleaned up uploaded file: {file_path}")
                    except:
                        pass
                    
                    return jsonify({
                        'success': False,
                        'message': 'This file contains data that already exists in the database. Please use a different file or clear the database first.',
                        'error_type': 'duplicate_data'
                    }), 400
                else:
                    raise parse_error
            
            # Clean up uploaded file after parsing
            try:
                os.remove(file_path)
                logger.info(f"Cleaned up uploaded file: {file_path}")
            except:
                pass
            
            success_message = f'Successfully processed PCAP file: {filename}'
            if 'warning' in parse_results:
                success_message += f' (Warning: {parse_results["warning"]})'
            
            return jsonify({
                'success': True,
                'message': success_message,
                'file_info': file_info,
                'parse_results': parse_results
            })
            
        except Exception as e:
            logger.error(f"Error uploading/parsing PCAP file: {e}")
            # Clean up file on error
            try:
                if 'file_path' in locals():
                    os.remove(file_path)
            except:
                pass
            
            error_message = str(e)
            if 'UNIQUE constraint failed' in error_message:
                error_message = 'This file contains data that already exists in the database. Please use a different file or clear the database first.'
            
            return jsonify({
                'success': False,
                'message': f'Error processing file: {error_message}'
            }), 500

    @app.route('/api/validate-pcap', methods=['POST'])
    def validate_pcap_endpoint():
        """Validate uploaded PCAP file without parsing"""
        try:
            if 'file' not in request.files:
                return jsonify({'valid': False, 'message': 'No file provided'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'valid': False, 'message': 'No file selected'}), 400
            
            # Save temporarily for validation
            upload_dir = os.path.join(app.instance_path, 'temp')
            os.makedirs(upload_dir, exist_ok=True)
            
            filename = secure_filename(file.filename)
            temp_path = os.path.join(upload_dir, filename)
            file.save(temp_path)
            
            try:
                # Validate file
                is_valid, info = validate_pcap_file(temp_path)
                
                if is_valid:
                    return jsonify({
                        'valid': True,
                        'message': 'Valid PCAP file',
                        'info': info
                    })
                else:
                    return jsonify({
                        'valid': False,
                        'message': f'Invalid PCAP file: {info}'
                    })
            finally:
                # Clean up temp file
                try:
                    os.remove(temp_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error validating PCAP file: {e}")
            return jsonify({
                'valid': False,
                'message': f'Validation error: {str(e)}'
            }), 500

    @app.route('/api/export-data')
    def api_export_data():
        """API endpoint for exporting data in various formats"""
        try:
            import csv
            import io
            from flask import make_response
            
            # Get parameters
            format_type = request.args.get('format', 'csv')
            time_range = request.args.get('time_range', '24h')
            include_packets = request.args.get('include_packets', 'true').lower() == 'true'
            include_flows = request.args.get('include_flows', 'true').lower() == 'true'
            include_stats = request.args.get('include_stats', 'true').lower() == 'true'
            
            # Calculate time filter
            time_delta = get_time_delta(time_range)
            time_filter = datetime.utcnow() - time_delta if time_delta else None
            
            export_data = {}
            
            # Export packets data
            if include_packets:
                packet_query = Packet.query
                if time_filter:
                    packet_query = packet_query.filter(Packet.timestamp >= time_filter)
                packets = packet_query.limit(10000).all()  # Limit for performance
                
                export_data['packets'] = [{
                    'id': p.id,
                    'timestamp': p.timestamp.isoformat(),
                    'source_ip': p.source_ip,
                    'dest_ip': p.dest_ip,
                    'source_port': p.source_port,
                    'dest_port': p.dest_port,
                    'protocol': p.protocol,
                    'packet_size': p.packet_size,
                    'flags': p.flags
                } for p in packets]
            
            # Export flows data
            if include_flows:
                flow_query = Flow.query
                if time_filter:
                    flow_query = flow_query.filter(Flow.start_time >= time_filter)
                
                # Apply status filter if provided
                status_filter = request.args.get('status')
                if status_filter and status_filter != 'all':
                    flow_query = flow_query.filter(Flow.status == status_filter.upper())
                
                # Apply protocol filter if provided
                protocol_filter = request.args.get('protocol')
                if protocol_filter and protocol_filter != 'all':
                    flow_query = flow_query.filter(Flow.protocol == protocol_filter.upper())
                
                # Apply limit
                limit = request.args.get('limit', '5000')
                if limit != 'all':
                    limit = min(int(limit), 10000)  # Cap at 10k for performance
                    flows = flow_query.limit(limit).all()
                else:
                    flows = flow_query.limit(10000).all()  # Still cap at 10k
                
                export_data['flows'] = [{
                    'id': f.id,
                    'source_ip': f.source_ip,
                    'dest_ip': f.dest_ip,
                    'source_port': f.source_port,
                    'dest_port': f.dest_port,
                    'protocol': f.protocol,
                    'start_time': f.start_time.isoformat(),
                    'end_time': f.end_time.isoformat() if f.end_time else None,
                    'packet_count': f.packet_count,
                    'total_bytes': f.total_bytes,
                    'status': f.status
                } for f in flows]
            
            # Export statistics
            if include_stats:
                total_packets = Packet.query.count()
                total_flows = Flow.query.count()
                active_flows = Flow.query.filter_by(status='ACTIVE').count()
                
                # Protocol distribution
                protocol_stats = db.session.query(
                    Packet.protocol,
                    func.count(Packet.id).label('count')
                ).group_by(Packet.protocol).all()
                
                export_data['statistics'] = {
                    'total_packets': total_packets,
                    'total_flows': total_flows,
                    'active_flows': active_flows,
                    'protocol_distribution': [
                        {'protocol': p.protocol, 'count': p.count}
                        for p in protocol_stats
                    ],
                    'export_timestamp': datetime.utcnow().isoformat(),
                    'time_range': time_range
                }
            
            # Generate response based on format
            if format_type == 'json':
                response = make_response(json.dumps(export_data, indent=2))
                response.headers['Content-Type'] = 'application/json'
                response.headers['Content-Disposition'] = f'attachment; filename=packetsight_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                
            elif format_type == 'csv':
                output = io.StringIO()
                
                # Write packets to CSV if included
                if include_packets and 'packets' in export_data:
                    writer = csv.DictWriter(output, fieldnames=[
                        'id', 'timestamp', 'source_ip', 'dest_ip', 'source_port',
                        'dest_port', 'protocol', 'packet_size', 'flags'
                    ])
                    writer.writeheader()
                    writer.writerows(export_data['packets'])
                
                response = make_response(output.getvalue())
                response.headers['Content-Type'] = 'text/csv'
                response.headers['Content-Disposition'] = f'attachment; filename=packetsight_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                
            else:
                return jsonify({'error': 'Unsupported format'}), 400
            
            return response
            
        except Exception as e:
            logger.error(f"Export data error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export-analytics')
    def api_export_analytics():
        try:
            import csv
            import io
            from flask import make_response
            
            format_type = request.args.get('format', 'csv')
            time_range = request.args.get('time_range', '24h')
            include_traffic = request.args.get('include_traffic', 'true').lower() == 'true'
            include_protocol = request.args.get('include_protocol', 'true').lower() == 'true'
            include_port = request.args.get('include_port', 'true').lower() == 'true'
            include_geo = request.args.get('include_geo', 'true').lower() == 'true'
        
            # Parse time range
            if time_range.endswith('h'):
                hours = int(time_range[:-1])
            elif time_range.endswith('d'):
                hours = int(time_range[:-1]) * 24
            else:
                hours = 24
                
            # Calculate time filter
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            analytics_data = {}
            
            # Traffic trends data
            if include_traffic:
                # Use strftime for SQLite compatibility instead of date_trunc
                traffic_data = db.session.query(
                    func.strftime('%Y-%m-%d %H:00:00', Packet.timestamp).label('hour'),
                    func.count(Packet.id).label('packets'),
                    func.sum(Packet.packet_size).label('bytes')
                ).filter(
                    Packet.timestamp >= start_time,
                    Packet.timestamp <= end_time
                ).group_by(func.strftime('%Y-%m-%d %H:00:00', Packet.timestamp)).order_by(func.strftime('%Y-%m-%d %H:00:00', Packet.timestamp)).all()
                
                analytics_data['traffic_trends'] = []
                for row in traffic_data:
                    try:
                        # Parse the hour string back to datetime for ISO format
                        hour_dt = datetime.strptime(row.hour, '%Y-%m-%d %H:%M:%S')
                        analytics_data['traffic_trends'].append({
                            'timestamp': hour_dt.isoformat(),
                            'packets': row.packets,
                            'bytes': row.bytes or 0
                        })
                    except:
                        # Fallback if parsing fails
                        analytics_data['traffic_trends'].append({
                            'timestamp': row.hour,
                            'packets': row.packets,
                            'bytes': row.bytes or 0
                        })
            
            # Protocol distribution data
            if include_protocol:
                protocol_data = db.session.query(
                    Packet.protocol,
                    func.count(Packet.id).label('count'),
                    func.sum(Packet.packet_size).label('bytes')
                ).filter(
                    Packet.timestamp >= start_time,
                    Packet.timestamp <= end_time
                ).group_by(Packet.protocol).order_by(desc('count')).limit(10).all()
                
                analytics_data['protocol_distribution'] = [
                    {
                        'protocol': row.protocol,
                        'count': row.count,
                        'bytes': row.bytes or 0
                    } for row in protocol_data
                ]
            
            # Port analysis data
            if include_port:
                port_data = db.session.query(
                    Packet.dest_port,
                    func.count(Packet.id).label('connections'),
                    func.sum(Packet.packet_size).label('volume')
                ).filter(
                    Packet.timestamp >= start_time,
                    Packet.timestamp <= end_time,
                    Packet.dest_port.isnot(None)
                ).group_by(Packet.dest_port).order_by(desc('connections')).limit(20).all()
                
                analytics_data['port_analysis'] = [
                    {
                        'port': row.dest_port,
                        'connections': row.connections,
                        'volume_bytes': row.volume or 0
                    } for row in port_data
                ]
            
            # Geographic analysis data
            if include_geo:
                geo_data = db.session.query(
                    Packet.source_ip,
                    Packet.dest_ip,
                    func.count(Packet.id).label('count')
                ).filter(
                    Packet.timestamp >= start_time,
                    Packet.timestamp <= end_time
                ).group_by(Packet.source_ip, Packet.dest_ip).order_by(desc('count')).limit(100).all()
                
                analytics_data['geographic_analysis'] = [
                    {
                        'source_ip': row.source_ip,
                        'destination_ip': row.dest_ip,
                        'connection_count': row.count
                    } for row in geo_data
                ]
            
            # Generate response based on format
            if format_type == 'json':
                response = make_response(jsonify(analytics_data))
                response.headers['Content-Disposition'] = f'attachment; filename=packetsight_analytics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                response.headers['Content-Type'] = 'application/json'
            else:  # CSV format
                output = io.StringIO()
                
                # Write traffic trends
                if include_traffic and 'traffic_trends' in analytics_data:
                    output.write("Traffic Trends\n")
                    output.write("Timestamp,Packets,Bytes\n")
                    for item in analytics_data['traffic_trends']:
                        output.write(f"{item['timestamp']},{item['packets']},{item['bytes']}\n")
                    output.write("\n")
                
                # Write protocol distribution
                if include_protocol and 'protocol_distribution' in analytics_data:
                    output.write("Protocol Distribution\n")
                    output.write("Protocol,Count,Bytes\n")
                    for item in analytics_data['protocol_distribution']:
                        output.write(f"{item['protocol']},{item['count']},{item['bytes']}\n")
                    output.write("\n")
                
                # Write port analysis
                if include_port and 'port_analysis' in analytics_data:
                    output.write("Port Analysis\n")
                    output.write("Port,Connections,Volume (Bytes)\n")
                    for item in analytics_data['port_analysis']:
                        output.write(f"{item['port']},{item['connections']},{item['volume_bytes']}\n")
                
                # Write geographic analysis
                if include_geo and 'geographic_analysis' in analytics_data:
                    output.write("\n")
                    output.write("Geographic Analysis\n")
                    output.write("Source IP,Destination IP,Connection Count\n")
                    for item in analytics_data['geographic_analysis']:
                        output.write(f"{item['source_ip']},{item['destination_ip']},{item['connection_count']}\n")
            
                response = make_response(output.getvalue())
                response.headers['Content-Disposition'] = f'attachment; filename=packetsight_analytics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                response.headers['Content-Type'] = 'text/csv'
            
            return response
        
        except Exception as e:
            logger.error(f"API export analytics error: {str(e)}")
            return jsonify({'error': str(e)}), 500