"""
Network Packet Simulator for Network Traffic Analyzer
Author: sharondelya
Description: Generates realistic network traffic data for testing and demonstration
"""

import random
import time
import hashlib
from datetime import datetime, timedelta
from simple_models import db, Packet, Flow, DNSQuery, HTTPTransaction
import logging

logger = logging.getLogger(__name__)


class PacketSimulator:
    """Simulates realistic network traffic patterns"""
    
    def __init__(self):
        self.common_ports = {
            'HTTP': [80, 8080, 8000, 3000, 5000],
            'HTTPS': [443, 8443, 9443],
            'FTP': [21, 22],
            'DNS': [53],
            'SSH': [22],
            'SMTP': [25, 587, 465],
            'IMAP': [143, 993],
            'POP3': [110, 995],
            'MYSQL': [3306],
            'POSTGRESQL': [5432],
            'REDIS': [6379],
            'MONGODB': [27017]
        }
        
        self.ip_pools = {
            'internal': [
                '192.168.1.{}', '192.168.2.{}', '10.0.1.{}', 
                '10.0.2.{}', '172.16.1.{}', '172.16.2.{}'
            ],
            'external': [
                '8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9',
                '74.125.224.{}', '151.101.129.{}', '104.16.132.{}',
                '172.217.12.{}', '142.250.191.{}', '23.185.0.{}'
            ]
        }
        
        self.domains = [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'reddit.com', 'discord.com', 'zoom.us'
        ]
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
            'Mozilla/5.0 (Android 11; Mobile; rv:91.0) Gecko/91.0'
        ]
    
    def generate_ip_address(self, pool='mixed'):
        """Generate a realistic IP address"""
        if pool == 'internal' or (pool == 'mixed' and random.random() < 0.7):
            # Generate internal IP
            template = random.choice(self.ip_pools['internal'])
            return template.format(random.randint(2, 254))
        else:
            # Generate external IP
            if '{}' in random.choice(self.ip_pools['external']):
                template = random.choice([ip for ip in self.ip_pools['external'] if '{}' in ip])
                return template.format(random.randint(1, 254))
            else:
                return random.choice(self.ip_pools['external'])
    
    def generate_packet(self, protocol=None, flow_id=None):
        """Generate a single realistic network packet"""
        if not protocol:
            protocol = random.choices(
                ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS'],
                weights=[40, 25, 5, 15, 10, 5]
            )[0]
        
        # Generate basic packet info
        source_ip = self.generate_ip_address('internal')
        dest_ip = self.generate_ip_address('external')
        timestamp = datetime.utcnow() - timedelta(
            seconds=random.randint(0, 3600)
        )
        
        # Protocol-specific packet generation
        if protocol == 'TCP':
            return self._generate_tcp_packet(source_ip, dest_ip, timestamp, flow_id)
        elif protocol == 'UDP':
            return self._generate_udp_packet(source_ip, dest_ip, timestamp, flow_id)
        elif protocol == 'HTTP':
            return self._generate_http_packet(source_ip, dest_ip, timestamp, flow_id)
        elif protocol == 'HTTPS':
            return self._generate_https_packet(source_ip, dest_ip, timestamp, flow_id)
        elif protocol == 'DNS':
            return self._generate_dns_packet(source_ip, dest_ip, timestamp)
        elif protocol == 'ICMP':
            return self._generate_icmp_packet(source_ip, dest_ip, timestamp)
        else:
            return self._generate_tcp_packet(source_ip, dest_ip, timestamp, flow_id)
    
    def _generate_tcp_packet(self, source_ip, dest_ip, timestamp, flow_id=None):
        """Generate TCP packet with realistic flags and options"""
        source_port = random.randint(32768, 65535)
        dest_port = random.choice([80, 443, 22, 25, 53, 993, 995, 3306, 5432])
        
        # TCP flags
        tcp_flags = random.choices([
            'SYN', 'ACK', 'SYN,ACK', 'FIN,ACK', 'RST', 'PSH,ACK'
        ], weights=[15, 40, 10, 10, 5, 20])[0]
        
        packet_size = random.randint(54, 1500)  # Including headers
        payload_size = max(0, packet_size - 54)  # Subtract TCP/IP headers
        
        # Generate payload preview for non-empty packets
        payload_preview = None
        if payload_size > 0:
            payload_preview = self._generate_payload_preview(dest_port, payload_size)
        
        packet = Packet(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol='TCP',
            packet_size=packet_size,
            payload_size=payload_size,
            flags=tcp_flags,
            ttl=random.randint(64, 255),
            payload_preview=payload_preview
        )
        
        return packet
    
    def _generate_udp_packet(self, source_ip, dest_ip, timestamp, flow_id=None):
        """Generate UDP packet"""
        source_port = random.randint(32768, 65535)
        dest_port = random.choice([53, 67, 68, 123, 161, 500, 4500])
        
        packet_size = random.randint(42, 1500)  # Including headers
        payload_size = max(0, packet_size - 42)  # Subtract UDP/IP headers
        
        payload_preview = None
        if payload_size > 0:
            payload_preview = self._generate_payload_preview(dest_port, payload_size)
        
        packet = Packet(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol='UDP',
            packet_size=packet_size,
            payload_size=payload_size,
            ttl=random.randint(64, 255),
            payload_preview=payload_preview
        )
        
        return packet
    
    def _generate_http_packet(self, source_ip, dest_ip, timestamp, flow_id=None):
        """Generate HTTP packet with realistic content"""
        source_port = random.randint(32768, 65535)
        dest_port = random.choice(self.common_ports['HTTP'])
        
        # HTTP methods and paths
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        method = random.choices(methods, weights=[70, 20, 5, 2, 2, 1])[0]
        
        paths = ['/', '/index.html', '/api/users', '/api/data', '/images/logo.png', 
                '/css/style.css', '/js/app.js', '/favicon.ico']
        path = random.choice(paths)
        
        # Generate HTTP-like payload preview
        payload_preview = f"{method} {path} HTTP/1.1\\r\\nHost: {random.choice(self.domains)}\\r\\n"
        
        packet_size = random.randint(200, 1500)
        payload_size = len(payload_preview.encode())
        
        packet = Packet(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol='HTTP',
            packet_size=packet_size,
            payload_size=payload_size,
            flags='PSH,ACK',
            ttl=random.randint(64, 255),
            payload_preview=payload_preview[:200]
        )
        
        return packet
    
    def _generate_https_packet(self, source_ip, dest_ip, timestamp, flow_id=None):
        """Generate HTTPS packet with encrypted payload"""
        source_port = random.randint(32768, 65535)
        dest_port = random.choice(self.common_ports['HTTPS'])
        
        # HTTPS payload is encrypted, so generate random-looking data
        payload_preview = "TLS encrypted data: " + "".join(
            random.choices('0123456789abcdef', k=40)
        )
        
        packet_size = random.randint(100, 1500)
        payload_size = packet_size - 54  # Subtract headers
        
        packet = Packet(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol='HTTPS',
            packet_size=packet_size,
            payload_size=payload_size,
            flags='PSH,ACK',
            ttl=random.randint(64, 255),
            payload_preview=payload_preview
        )
        
        return packet
    
    def _generate_dns_packet(self, source_ip, dest_ip, timestamp):
        """Generate DNS query packet and create DNS record"""
        source_port = random.randint(32768, 65535)
        dest_port = 53
        
        domain = random.choice(self.domains)
        query_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        query_type = random.choices(query_types, weights=[60, 20, 8, 5, 4, 3])[0]
        
        payload_preview = f"DNS Query: {domain} ({query_type})"
        packet_size = random.randint(64, 200)
        payload_size = packet_size - 42
        
        # Create DNS query record
        dns_query = DNSQuery(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            query_name=domain,
            query_type=query_type,
            response_code=random.choice([0, 0, 0, 3, 2]),  # Mostly success
            response_time=random.uniform(10, 200),
            is_cached=random.choice([True, False])
        )
        
        packet = Packet(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol='DNS',
            packet_size=packet_size,
            payload_size=payload_size,
            ttl=random.randint(64, 255),
            payload_preview=payload_preview
        )
        
        # Store both records
        try:
            db.session.add(dns_query)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to save DNS query: {e}")
            db.session.rollback()
        
        return packet
    
    def _generate_icmp_packet(self, source_ip, dest_ip, timestamp):
        """Generate ICMP packet"""
        icmp_types = ['Echo Request', 'Echo Reply', 'Destination Unreachable', 
                     'Time Exceeded', 'Parameter Problem']
        icmp_type = random.choice(icmp_types)
        
        payload_preview = f"ICMP {icmp_type}"
        packet_size = random.randint(64, 100)
        payload_size = packet_size - 34  # ICMP + IP headers
        
        packet = Packet(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol='ICMP',
            packet_size=packet_size,
            payload_size=payload_size,
            ttl=random.randint(64, 255),
            payload_preview=payload_preview
        )
        
        return packet
    
    def _generate_payload_preview(self, dest_port, payload_size):
        """Generate realistic payload preview based on port"""
        if dest_port in [80, 8080, 8000]:
            return "HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n"
        elif dest_port == 443:
            return "TLS handshake or encrypted HTTP data"
        elif dest_port == 22:
            return "SSH protocol data"
        elif dest_port == 25:
            return "SMTP: MAIL FROM:<user@domain.com>"
        elif dest_port == 53:
            return "DNS query data"
        elif dest_port in [993, 995]:
            return "Encrypted email data"
        else:
            # Generic payload
            return f"Application data ({payload_size} bytes)"
    
    def generate_traffic_batch(self, count=100, protocols=None):
        """Generate a batch of network traffic"""
        if not protocols:
            protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']
        
        packets = []
        generated_count = 0
        
        try:
            for _ in range(count):
                protocol = random.choice(protocols)
                packet = self.generate_packet(protocol)
                
                if packet:
                    packets.append(packet)
                    generated_count += 1
            
            # Bulk save to database
            if packets:
                db.session.add_all(packets)
                db.session.commit()
                logger.info(f"Generated and saved {generated_count} packets")
            
            return generated_count
        
        except Exception as e:
            logger.error(f"Error generating traffic batch: {e}")
            db.session.rollback()
            return 0
    
    def generate_realistic_flow(self, protocol='TCP', duration_minutes=5):
        """Generate a realistic network flow with multiple packets"""
        try:
            # Create flow
            source_ip = self.generate_ip_address('internal')
            dest_ip = self.generate_ip_address('external')
            source_port = random.randint(32768, 65535)
            
            if protocol == 'HTTP':
                dest_port = random.choice(self.common_ports['HTTP'])
            elif protocol == 'HTTPS':
                dest_port = random.choice(self.common_ports['HTTPS'])
            else:
                dest_port = random.choice([80, 443, 22, 25, 53])
            
            # Generate flow ID
            flow_identifier = f"{source_ip}:{source_port}-{dest_ip}:{dest_port}-{protocol}"
            flow_hash = hashlib.md5(flow_identifier.encode()).hexdigest()[:16]
            
            start_time = datetime.utcnow() - timedelta(minutes=random.randint(0, 60))
            end_time = start_time + timedelta(minutes=duration_minutes)
            
            # Create flow record
            flow = Flow(
                flow_id=flow_hash,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                start_time=start_time,
                end_time=end_time,
                duration=duration_minutes * 60,
                status='CLOSED' if random.random() < 0.8 else 'ACTIVE'
            )
            
            db.session.add(flow)
            db.session.flush()  # Get the flow ID
            
            # Generate packets for this flow
            packet_count = random.randint(10, 100)
            packets = []
            total_bytes = 0
            
            for i in range(packet_count):
                packet_time = start_time + timedelta(
                    seconds=random.randint(0, duration_minutes * 60)
                )
                
                packet = self.generate_packet(protocol, flow.id)
                packet.timestamp = packet_time
                packet.source_ip = source_ip
                packet.dest_ip = dest_ip
                packet.source_port = source_port
                packet.dest_port = dest_port
                
                packets.append(packet)
                total_bytes += packet.packet_size
            
            # Update flow statistics
            flow.packet_count = packet_count
            flow.total_bytes = total_bytes
            
            # Save all records
            db.session.add_all(packets)
            db.session.commit()
            
            logger.info(f"Generated flow {flow_hash} with {packet_count} packets")
            return flow.id
        
        except Exception as e:
            logger.error(f"Error generating realistic flow: {e}")
            db.session.rollback()
            return None
    
    def simulate_continuous_traffic(self, duration_seconds=300, packets_per_second=10):
        """Simulate continuous network traffic for a specified duration"""
        logger.info(f"Starting traffic simulation for {duration_seconds} seconds")
        
        start_time = time.time()
        total_generated = 0
        
        try:
            while time.time() - start_time < duration_seconds:
                batch_size = min(packets_per_second, 50)  # Limit batch size
                generated = self.generate_traffic_batch(batch_size)
                total_generated += generated
                
                # Sleep to maintain the desired rate
                time.sleep(1.0)
            
            logger.info(f"Traffic simulation completed. Generated {total_generated} packets")
            return total_generated
        
        except Exception as e:
            logger.error(f"Error in continuous traffic simulation: {e}")
            return total_generated