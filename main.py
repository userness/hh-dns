#!/usr/bin/env python3

import socket
import threading
import os
from typing import Tuple, Optional

class DNSServer:
def **init**(self, listen_port: int = 53, upstream_dns: str = “8.8.8.8”, domains_file: str = “domains.txt”):
self.listen_port = listen_port
self.upstream_dns = upstream_dns
self.domains_file = domains_file
self.socket = None
self.domain_mappings = {}
self.load_domain_mappings()

```
def load_domain_mappings(self):
    self.domain_mappings = {}
    
    if not os.path.exists(self.domains_file):
        return
    
    try:
        with open(self.domains_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '->' not in line:
                    continue
                
                source, target = line.split('->', 1)
                source = source.strip()
                target = target.strip()
                
                if not source.startswith('.'):
                    source = '.' + source
                
                self.domain_mappings[source] = target
    
    except Exception as e:
        print(f"Error loading domain mappings: {e}")
    
def start(self):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.socket.bind(('0.0.0.0', self.listen_port))
    print(f"DNS Server listening on port {self.listen_port}")
    
    try:
        while True:
            data, addr = self.socket.recvfrom(512)
            thread = threading.Thread(target=self.handle_request, args=(data, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\nShutting down DNS server...")
    finally:
        if self.socket:
            self.socket.close()

def handle_request(self, data: bytes, addr: Tuple[str, int]):
    try:
        domain = self.parse_dns_query(data)
        if not domain:
            return
        
        redirect_target = None
        for extension, target_suffix in self.domain_mappings.items():
            if domain.endswith(extension):
                base_domain = domain[:-len(extension)]
                redirect_target = base_domain + target_suffix
                break
        
        if redirect_target:
            response = self.create_redirect_response(data, redirect_target)
        else:
            response = self.forward_to_upstream(data)
        
        if response:
            self.socket.sendto(response, addr)
            
    except Exception as e:
        print(f"Error handling request: {e}")

def parse_dns_query(self, data: bytes) -> Optional[str]:
    try:
        offset = 12
        domain_parts = []
        
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            if length > 63:
                break
            
            offset += 1
            if offset + length > len(data):
                break
                
            part = data[offset:offset + length].decode('utf-8')
            domain_parts.append(part)
            offset += length
        
        return '.'.join(domain_parts) if domain_parts else None
        
    except Exception:
        return None

def create_redirect_response(self, query: bytes, target_domain: str) -> bytes:
    try:
        target_ip = socket.gethostbyname(target_domain)
        ip_bytes = socket.inet_aton(target_ip)
        
        response = bytearray(query)
        
        response[2] = 0x81
        response[3] = 0x80
        
        response[6] = 0x00
        response[7] = 0x01
        
        response.extend([0xc0, 0x0c])
        response.extend([0x00, 0x01])
        response.extend([0x00, 0x01])
        response.extend([0x00, 0x00, 0x01, 0x2c])
        response.extend([0x00, 0x04])
        response.extend(ip_bytes)
        
        return bytes(response)
        
    except Exception as e:
        print(f"Error creating redirect response: {e}")
        return None

def forward_to_upstream(self, query: bytes) -> Optional[bytes]:
    try:
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_socket.settimeout(5.0)
        
        upstream_socket.sendto(query, (self.upstream_dns, 53))
        
        response, _ = upstream_socket.recvfrom(512)
        upstream_socket.close()
        
        return response
        
    except Exception as e:
        print(f"Error forwarding to upstream DNS: {e}")
        return None
```

def main():
try:
server = DNSServer(listen_port=53)
server.start()
except PermissionError:
print(“Permission denied. Trying port 5353…”)
server = DNSServer(listen_port=5353)
server.start()

if **name** == “**main**”:
main()
