#!/usr/bin/env python3
import sys
import socket
import select
import threading
import ipaddress
import os

allow_domains = sys.argv[1].split(',') if sys.argv[1] else []
deny_domains = sys.argv[2].split(',') if sys.argv[2] else []
allow_ips = [ipaddress.ip_network(x) for x in sys.argv[3].split(',')] if sys.argv[3] else []
deny_ips = [ipaddress.ip_network(x) for x in sys.argv[4].split(',')] if sys.argv[4] else []

default_allow = not (allow_domains or allow_ips)

def domain_match(domain, pattern):
    if pattern.startswith('*.'):
        return domain == pattern[2:] or domain.endswith(pattern[1:])
    return domain == pattern

def is_allowed_domain(domain):
    best_len = -1
    allowed = default_allow
    
    for p in allow_domains:
        if domain_match(domain, p) and len(p) > best_len:
            best_len = len(p)
            allowed = True
            
    for p in deny_domains:
        if domain_match(domain, p) and len(p) > best_len:
            best_len = len(p)
            allowed = False
            
    return allowed

def is_allowed_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
        
    best_prefix = -1
    allowed = default_allow
    
    for net in allow_ips:
        if ip in net and net.prefixlen > best_prefix:
            best_prefix = net.prefixlen
            allowed = True
            
    for net in deny_ips:
        if ip in net and net.prefixlen > best_prefix:
            best_prefix = net.prefixlen
            allowed = False
            
    return allowed

def is_allowed(host):
    try:
        ipaddress.ip_address(host)
        return is_allowed_ip(host)
    except ValueError:
        return is_allowed_domain(host)

def handle_client(client_sock):
    try:
        req = client_sock.recv(8192)
        if not req: return
        
        first_line = req.split(b'\r\n')[0].decode('utf-8', 'ignore')
        method, url, _ = first_line.split(' ', 2)
        
        if method == "CONNECT":
            host, port = url.split(':')
            port = int(port)
        else:
            if "://" in url:
                url = url.split("://")[1]
            host = url.split('/')[0]
            port = 80
            if ':' in host:
                host, port_str = host.split(':')
                port = int(port_str)
                
        if not is_allowed(host):
            client_sock.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
            
        remote_sock = socket.create_connection((host, port), timeout=10)
        
        if method == "CONNECT":
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            remote_sock.sendall(req)
            
        sockets = [client_sock, remote_sock]
        while True:
            r, _, _ = select.select(sockets, [], [], 60)
            if not r: break # timeout
            
            if client_sock in r:
                data = client_sock.recv(8192)
                if not data: break
                remote_sock.sendall(data)
            if remote_sock in r:
                data = remote_sock.recv(8192)
                if not data: break
                client_sock.sendall(data)
    except Exception:
        pass
    finally:
        client_sock.close()
        try:
            remote_sock.close()
        except:
            pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 8888))
    server.listen(100)
    
    with open('/sidecar_shared/ready', 'w') as f:
        f.write('ready\n')
    
    while True:
        try:
            client, _ = server.accept()
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        except KeyboardInterrupt:
            break

if __name__ == '__main__':
    main()
