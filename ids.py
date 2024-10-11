import pyshark
import ipaddress
import json
import requests
import time
import base64

class Packet:
    def __init__(self, time_stamp: str = '', ipsrc: str = '', ipdst: str = '', srcport: str = '', dstport: str = '', transport_layer: str = '', highest_layer: str = '', payload: str = ''):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstport = dstport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer
        self.payload = payload

class APIServer:
    def __init__(self, ip: str, port: str):
        self.ip = ip
        self.port = port

# Signature rules (basic examples)
SIGNATURES = {
    'port_scan': {'ports': [80, 8080, 443, 22], 'threshold': 10},
    'icmp_flood': {'protocol': 'ICMP', 'threshold': 50},
    'syn_flood': {'syn_threshold': 100},
    'dns_amplification': {'dns_response_threshold': 512},
    'http_flood': {'http_threshold': 50},
    'suspicious_user_agents': ['sqlmap', 'curl', 'python-requests', 'nmap'],
    'malicious_payload': ['malicious', 'attack', 'password', 'exploit'],
}

packet_counts = {
    'icmp': 0,
    'syn': 0,
    'http': 0,
    'time': time.time(),
}

server = APIServer('127.0.0.1', '8080')

def is_api_server(packet, server: APIServer) -> bool:
    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
        return packet.ip.src == server.ip or packet.ip.dst == server.ip
    return False

def is_private_ip(ip_address: str) -> bool:
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private

def report(message: Packet, alert_type='info'):
    packet_dict = {
        "time_stamp": message.time_stamp,
        "ipsrc": message.ipsrc,
        "ipdst": message.ipdst,
        "srcport": message.srcport,
        "dstport": message.dstport,
        "transport_layer": message.transport_layer,
        "highest_layer": message.highest_layer,
        "payload": message.payload,
    }

    json_payload = json.dumps(packet_dict)
    b64_payload = base64.b64encode(json_payload.encode('utf-8')).decode('utf-8')

    print(f"[{alert_type.upper()}] {json_payload}")

    try:
        response = requests.get(f'http://{server.ip}:{server.port}/api/?data={b64_payload}')
        if response.status_code != 200:
            print("Failed to report to server:", response.status_code)
    except requests.ConnectionError:
        print("Failed to connect to reporting server")

def check_payload(packet):
    try:
        if hasattr(packet, 'data') and packet.data.text:
            payload = packet.data.text.lower()
            for keyword in SIGNATURES['malicious_payload']:
                if keyword in payload:
                    alert(f"Suspicious keyword found in payload: {keyword}", packet.ip.src)
                    return True
    except AttributeError:
        pass
    return False

def check_signatures(packet):
    src_ip = packet.ip.src
    dst_port = int(packet.tcp.dstport) if hasattr(packet, 'tcp') else None

    # Check for port scan
    if packet.transport_layer == 'TCP' and dst_port in SIGNATURES['port_scan']['ports']:
        if 'tcp' not in packet_counts:
            packet_counts['tcp'] = set()
        packet_counts['tcp'].add(dst_port)

        if len(packet_counts['tcp']) > SIGNATURES['port_scan']['threshold']:
            alert("Potential port scanning detected!", src_ip)
            return True

    # Check for ICMP flood
    if hasattr(packet, 'icmp'):
        packet_counts['icmp'] += 1
        if packet_counts['icmp'] > SIGNATURES['icmp_flood']['threshold']:
            alert("ICMP flood detected!", packet.ip.src)
            return True

    # Check for SYN flood
    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and packet.tcp.flags == '0x02':
        packet_counts['syn'] += 1
        if packet_counts['syn'] > SIGNATURES['syn_flood']['syn_threshold']:
            alert("SYN flood detected!", src_ip)
            return True

    # Check for DNS amplification
    if hasattr(packet, 'dns') and int(packet.dns.length) > SIGNATURES['dns_amplification']['dns_response_threshold']:
        alert(f"DNS amplification detected! Response size: {packet.dns.length}", src_ip)
        return True

    # Check for HTTP flood
    if hasattr(packet, 'http'):
        packet_counts['http'] += 1
        if packet_counts['http'] > SIGNATURES['http_flood']['http_threshold']:
            alert("HTTP flood detected!", src_ip)
            return True

        if hasattr(packet.http, 'user_agent'):
            user_agent = packet.http.user_agent.lower()
            for suspicious_agent in SIGNATURES['suspicious_user_agents']:
                if suspicious_agent in user_agent:
                    alert(f"Suspicious User-Agent detected: {user_agent}", src_ip)
                    return True

    # Check for malicious payload content
    if check_payload(packet):
        return True

    return False

def alert(message, ip_address):
    print(f"[ALERT] {message} Source IP: {ip_address}")
    DataGram = Packet(time_stamp=time.time(), ipsrc=ip_address, ipdst='', srcport='', dstport='', transport_layer='', highest_layer='ALERT')
    report(DataGram, alert_type='alert')

def filter(packet):
    if is_api_server(packet, server):
        return

    if time.time() - packet_counts['time'] > 10:
        packet_counts['icmp'] = 0
        packet_counts['syn'] = 0
        packet_counts['http'] = 0
        packet_counts['time'] = time.time()

    if hasattr(packet, 'icmp'):
        DataGram = Packet()
        DataGram.ipdst = packet.ip.dst
        DataGram.ipsrc = packet.ip.src
        DataGram.highest_layer = packet.highest_layer
        DataGram.time_stamp = packet.sniff_timestamp
        report(DataGram)

    if packet.transport_layer in ['TCP', 'UDP']:
        DataGram = Packet()
        if hasattr(packet, 'ip') and is_private_ip(packet.ip.src) and is_private_ip(packet.ip.dst):
            DataGram.ipsrc = packet.ip.src
            DataGram.ipdst = packet.ip.dst
            DataGram.time_stamp = packet.sniff_timestamp
            DataGram.transport_layer = packet.transport_layer
            DataGram.highest_layer = packet.highest_layer

            if hasattr(packet, 'udp'):
                DataGram.dstport = packet.udp.dstport
                DataGram.srcport = packet.udp.srcport

            if hasattr(packet, 'tcp'):
                DataGram.dstport = packet.tcp.dstport
                DataGram.srcport = packet.tcp.srcport

            report(DataGram)
            check_signatures(packet)

capture = pyshark.LiveCapture(interface=r'\Device\NPF_{F3B9F27C-3321-4503-80BF-F513FBD62CF1}', display_filter='ip')
capture.apply_on_packets(filter, timeout=100)
