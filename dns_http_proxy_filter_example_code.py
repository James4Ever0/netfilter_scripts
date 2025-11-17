import socket
import threading
from dnslib import DNSRecord, RR, A, QTYPE
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import time
import re

# Configuration
UPSTREAM_DNS = "8.8.8.8"
PROXY_PORT = 8080
DNS_PORT = 53
WHITELIST = {"example.com", "safe.org"}

class DNSCache:
    def __init__(self):
        self.cache = {}  # Format: {domain: {"ips": set(), "expiry": timestamp}}
    
    def update(self, domain, ips, ttl):
        self.cache[domain] = {
            "ips": set(ips),
            "expiry": time.time() + ttl
        }
    
    def get_ips(self, domain):
        record = self.cache.get(domain)
        if record and record["expiry"] > time.time():
            return record["ips"]
        return None

dns_cache = DNSCache()

def dns_proxy():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", DNS_PORT))
    
    while True:
        data, addr = udp_sock.recvfrom(1024)
        req = DNSRecord.parse(data)
        qname = str(req.q.qname).rstrip('.')
        
        # Forward query upstream
        res = DNSRecord.parse(socket.gethostbyname(UPSTREAM_DNS))
        
        # Process response
        ips = [str(r.rdata) for r in res.rr if r.rtype == QTYPE.A]
        if qname in WHITELIST:
            dns_cache.update(qname, ips, res.auth[0].ttl)
            udp_sock.sendto(res.pack(), addr)
        else:
            # Send NXDOMAIN for blocked domains
            res.header.rcode = 3
            udp_sock.sendto(res.pack(), addr)

class ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        host, _, port = self.path.partition(':')
        port = int(port) if port else 443
        
        if self.is_blocked(host):
            self.send_error(403, "Domain not whitelisted")
            return
        
        # Connect to upstream server
        try:
            upstream = socket.create_connection((host, port))
            self.send_response(200, "Connection Established")
            self.end_headers()
        except Exception:
            self.send_error(502)
            return
        
        # Tunnel traffic
        self.tunnel(self.connection, upstream)
    
    def do_GET(self):
        parsed = urlparse(self.path)
        host = parsed.hostname
        
        if self.is_blocked(host):
            self.send_error(403, "Direct IP access denied")
            return
        
        # Additional request filtering
        if self.is_malicious(self.path):
            self.send_error(400, "Malicious request detected")
            return
        
        # Forward valid request
        self.proxy_request()
    
    def is_blocked(self, host):
        # Reject direct IP access
        try:
            socket.inet_aton(host)
            return True  # Block IPs
        except socket.error:
            pass
        
        # Check DNS cache
        ips = dns_cache.get_ips(host)
        return not (ips and host in WHITELIST)
    
    def is_malicious(self, path):
        # Basic threat detection
        patterns = [
            r"../", r"\.\./",  # Path traversal
            r"<script>",        # XSS
            r"union\s+select", # SQLi
            r"exec\(|eval\("   # Code injection
        ]
        return any(re.search(p, path, re.I) for p in patterns)

if __name__ == "__main__":
    # Start DNS proxy thread
    threading.Thread(target=dns_proxy, daemon=True).start()
    
    # Start HTTP proxy
    HTTPServer(("0.0.0.0", PROXY_PORT), ProxyHandler).serve_forever()