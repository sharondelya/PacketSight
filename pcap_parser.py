"""
PCAP File Parser for Network Traffic Analyzer
Author: sharondelya
Description: Parse PCAP/PCAPNG files and extract real network traffic data
"""

import os
import logging
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from simple_models import db, Packet, Flow, DNSQuery, HTTPTransaction
import hashlib

logger = logging.getLogger(__name__)


class PCAPParser:
    """Parse PCAP files and extract network traffic data"""
    
    def __init__(self):
        self.supported_formats = ['.pcap', '.pcapng', '.cap']
        self.parsed_packets = 0
        self.flows = {}
        
    def parse_file(self, file_path, max_packets=None):
        """
        Parse a PCAP file and extract network traffic data
        
        Args:
            file_path (str): Path to the PCAP file
            max_packets (int): Maximum number of packets to parse (None for all)
            
        Returns:
            dict: Parsing results with statistics
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
            
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
            
        logger.info(f"Starting to parse PCAP file: {file_path}")
        
        try:
            # Read PCAP file using scapy
            packets = rdpcap(file_path)
            total_packets = len(packets)
            
            if max_packets:
                packets = packets[:max_packets]
                
            logger.info(f"Found {total_packets} packets in file, processing {len(packets)}")
            
            # Parse packets
            parsed_data = {
                'packets': [],
                'flows': [],
                'dns_queries': [],
                'http_transactions': [],
                'statistics': {
                    'total_packets': len(packets),
                    'parsed_packets': 0,
                    'protocols': {},
                    'start_time': None,
                    'end_time': None,
                    'duration': 0
                }
            }
            
            for i, pkt in enumerate(packets):
                try:
                    parsed_packet = self._parse_packet(pkt, i)
                    if parsed_packet:
                        parsed_data['packets'].append(parsed_packet)
                        parsed_data['statistics']['parsed_packets'] += 1
                        
                        # Update protocol statistics
                        protocol = parsed_packet.protocol
                        if protocol not in parsed_data['statistics']['protocols']:
                            parsed_data['statistics']['protocols'][protocol] = 0
                        parsed_data['statistics']['protocols'][protocol] += 1
                        
                        # Track time range
                        if not parsed_data['statistics']['start_time']:
                            parsed_data['statistics']['start_time'] = parsed_packet.timestamp
                        parsed_data['statistics']['end_time'] = parsed_packet.timestamp
                        
                except Exception as e:
                    logger.warning(f"Error parsing packet {i}: {e}")
                    continue
            
            # Calculate duration
            if parsed_data['statistics']['start_time'] and parsed_data['statistics']['end_time']:
                duration = (parsed_data['statistics']['end_time'] - parsed_data['statistics']['start_time']).total_seconds()
                parsed_data['statistics']['duration'] = duration
            
            # Generate flows from parsed packets
            parsed_data['flows'] = self._generate_flows_from_packets(parsed_data['packets'])
            
            # Save to database
            self._save_to_database(parsed_data)
            
            logger.info(f"Successfully parsed {parsed_data['statistics']['parsed_packets']} packets")
            return parsed_data['statistics']
            
        except Exception as e:
            logger.error(f"Error parsing PCAP file: {e}")
            raise
    
    def _parse_packet(self, pkt, packet_index):
        """Parse a single packet and extract relevant information"""
        try:
            # Skip non-IP packets
            if not pkt.haslayer(IP):
                return None
                
            ip_layer = pkt[IP]
            timestamp = datetime.fromtimestamp(float(pkt.time))
            
            # Basic packet information
            packet_data = Packet(
                timestamp=timestamp,
                source_ip=ip_layer.src,
                dest_ip=ip_layer.dst,
                packet_size=len(pkt),
                ttl=ip_layer.ttl,
                protocol='IP'
            )
            
            # Parse transport layer
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                packet_data.protocol = 'TCP'
                packet_data.source_port = tcp_layer.sport
                packet_data.dest_port = tcp_layer.dport
                packet_data.flags = self._get_tcp_flags(tcp_layer)
                
                # Check for HTTP
                if tcp_layer.dport in [80, 8080] or tcp_layer.sport in [80, 8080]:
                    if pkt.haslayer(Raw):
                        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                        if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                            packet_data.protocol = 'HTTP'
                            packet_data.payload_preview = payload[:200]
                            self._parse_http_transaction(pkt, timestamp)
                
                # Check for HTTPS
                elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    packet_data.protocol = 'HTTPS'
                    packet_data.payload_preview = "TLS encrypted data"
                    
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                packet_data.protocol = 'UDP'
                packet_data.source_port = udp_layer.sport
                packet_data.dest_port = udp_layer.dport
                
                # Check for DNS
                if udp_layer.dport == 53 or udp_layer.sport == 53:
                    packet_data.protocol = 'DNS'
                    if pkt.haslayer(DNS):
                        self._parse_dns_query(pkt, timestamp)
                        
            elif pkt.haslayer(ICMP):
                icmp_layer = pkt[ICMP]
                packet_data.protocol = 'ICMP'
                packet_data.payload_preview = f"ICMP Type: {icmp_layer.type}"
            
            # Calculate payload size
            if pkt.haslayer(Raw):
                packet_data.payload_size = len(pkt[Raw].load)
                if not packet_data.payload_preview:
                    # Show first 50 bytes of payload as hex
                    payload_bytes = pkt[Raw].load[:50]
                    packet_data.payload_preview = ' '.join(f'{b:02x}' for b in payload_bytes)
            else:
                packet_data.payload_size = 0
            
            return packet_data
            
        except Exception as e:
            logger.warning(f"Error parsing packet {packet_index}: {e}")
            return None
    
    def _get_tcp_flags(self, tcp_layer):
        """Extract TCP flags as a string"""
        flags = []
        if tcp_layer.flags.F: flags.append('FIN')
        if tcp_layer.flags.S: flags.append('SYN')
        if tcp_layer.flags.R: flags.append('RST')
        if tcp_layer.flags.P: flags.append('PSH')
        if tcp_layer.flags.A: flags.append('ACK')
        if tcp_layer.flags.U: flags.append('URG')
        return ','.join(flags) if flags else 'NONE'
    
    def _parse_dns_query(self, pkt, timestamp):
        """Parse DNS query and create DNS record"""
        try:
            if not pkt.haslayer(DNS):
                return
                
            dns_layer = pkt[DNS]
            ip_layer = pkt[IP]
            
            # Only process queries (not responses)
            if dns_layer.qr == 0:  # Query
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                query_type = dns_layer.qd.qtype
                
                # Map query type numbers to names
                qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
                query_type_name = qtype_map.get(query_type, str(query_type))
                
                dns_query = DNSQuery(
                    timestamp=timestamp,
                    source_ip=ip_layer.src,
                    dest_ip=ip_layer.dst,
                    query_name=query_name,
                    query_type=query_type_name,
                    response_code=0,  # Will be updated if response is found
                    response_time=0,  # Will be calculated if response is found
                    is_cached=False
                )
                
                # Store for later database insertion
                if not hasattr(self, '_dns_queries'):
                    self._dns_queries = []
                self._dns_queries.append(dns_query)
                
        except Exception as e:
            logger.warning(f"Error parsing DNS query: {e}")
    
    def _parse_http_transaction(self, pkt, timestamp):
        """Parse HTTP transaction and create HTTP record"""
        try:
            if not pkt.haslayer(Raw):
                return
                
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            lines = payload.split('\r\n')
            
            if not lines:
                return
                
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            
            if len(parts) >= 3:
                method = parts[0]
                url = parts[1]
                
                # Extract headers
                host = None
                user_agent = None
                content_type = None
                
                for line in lines[1:]:
                    if line.startswith('Host: '):
                        host = line[6:]
                    elif line.startswith('User-Agent: '):
                        user_agent = line[12:]
                    elif line.startswith('Content-Type: '):
                        content_type = line[14:]
                
                # Build full URL
                if host:
                    full_url = f"http://{host}{url}"
                else:
                    full_url = url
                
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                
                http_transaction = HTTPTransaction(
                    timestamp=timestamp,
                    source_ip=ip_layer.src,
                    dest_ip=ip_layer.dst,
                    method=method,
                    url=full_url,
                    host=host or ip_layer.dst,
                    status_code=0,  # Will be updated if response is found
                    response_time=0,  # Will be calculated if response is found
                    request_size=len(pkt),
                    response_size=0,  # Will be updated if response is found
                    user_agent=user_agent,
                    content_type=content_type,
                    is_ssl=tcp_layer.dport == 443 or tcp_layer.sport == 443
                )
                
                # Store for later database insertion
                if not hasattr(self, '_http_transactions'):
                    self._http_transactions = []
                self._http_transactions.append(http_transaction)
                
        except Exception as e:
            logger.warning(f"Error parsing HTTP transaction: {e}")
    
    def _generate_flows_from_packets(self, packets):
        """Generate network flows from parsed packets"""
        flows = {}
        
        for packet in packets:
            if not packet.source_port or not packet.dest_port:
                continue
                
            # Create flow identifier
            flow_key = f"{packet.source_ip}:{packet.source_port}-{packet.dest_ip}:{packet.dest_port}-{packet.protocol}"
            reverse_key = f"{packet.dest_ip}:{packet.dest_port}-{packet.source_ip}:{packet.source_port}-{packet.protocol}"
            
            # Check if flow exists (in either direction)
            if flow_key in flows:
                flow = flows[flow_key]
            elif reverse_key in flows:
                flow = flows[reverse_key]
            else:
                # Create new flow
                flow_id = hashlib.md5(flow_key.encode()).hexdigest()[:16]
                flow = Flow(
                    flow_id=flow_id,
                    source_ip=packet.source_ip,
                    dest_ip=packet.dest_ip,
                    source_port=packet.source_port,
                    dest_port=packet.dest_port,
                    protocol=packet.protocol,
                    start_time=packet.timestamp,
                    end_time=packet.timestamp,
                    packet_count=0,
                    total_bytes=0,
                    status='ACTIVE'
                )
                flows[flow_key] = flow
            
            # Update flow statistics
            flow.packet_count += 1
            flow.total_bytes += packet.packet_size
            flow.end_time = packet.timestamp
            
            # Calculate duration
            if flow.start_time and flow.end_time:
                flow.duration = (flow.end_time - flow.start_time).total_seconds()
        
        # Mark flows as closed (since we're parsing historical data)
        for flow in flows.values():
            flow.status = 'CLOSED'
        
        return list(flows.values())
    
    def _save_to_database(self, parsed_data):
        """Save parsed data to database"""
        try:
            logger.info("Saving parsed data to database...")
            
            # Save packets
            if parsed_data['packets']:
                db.session.add_all(parsed_data['packets'])
                logger.info(f"Saving {len(parsed_data['packets'])} packets")
            
            # Save flows
            if parsed_data['flows']:
                db.session.add_all(parsed_data['flows'])
                logger.info(f"Saving {len(parsed_data['flows'])} flows")
            
            # Save DNS queries
            if hasattr(self, '_dns_queries') and self._dns_queries:
                db.session.add_all(self._dns_queries)
                logger.info(f"Saving {len(self._dns_queries)} DNS queries")
            
            # Save HTTP transactions
            if hasattr(self, '_http_transactions') and self._http_transactions:
                db.session.add_all(self._http_transactions)
                logger.info(f"Saving {len(self._http_transactions)} HTTP transactions")
            
            # Commit all changes
            db.session.commit()
            logger.info("Successfully saved all parsed data to database")
            
        except Exception as e:
            logger.error(f"Error saving parsed data to database: {e}")
            db.session.rollback()
            raise
    
    def get_file_info(self, file_path):
        """Get information about a PCAP file without parsing it"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Get basic file info
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext not in self.supported_formats:
                raise ValueError(f"Unsupported file format: {file_ext}")
            
            # Quick scan to get packet count and time range
            packets = rdpcap(file_path)
            packet_count = len(packets)
            
            start_time = None
            end_time = None
            
            if packets:
                start_time = datetime.fromtimestamp(float(packets[0].time))
                end_time = datetime.fromtimestamp(float(packets[-1].time))
            
            return {
                'file_path': file_path,
                'file_size': file_size,
                'file_size_mb': round(file_size / (1024 * 1024), 2),
                'format': file_ext,
                'packet_count': packet_count,
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': end_time.isoformat() if end_time else None,
                'duration': (end_time - start_time).total_seconds() if start_time and end_time else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            raise


def validate_pcap_file(file_path):
    """Validate if a file is a valid PCAP file"""
    try:
        parser = PCAPParser()
        info = parser.get_file_info(file_path)
        return True, info
    except Exception as e:
        return False, str(e)