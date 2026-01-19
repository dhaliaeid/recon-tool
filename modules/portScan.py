"""
Port Scanner Module
Scans for open TCP ports on target
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def scan_port(host, port, timeout=1):
    """
    Scan a single port
    
    Args:
        host (str): Target host
        port (int): Port number
        timeout (int): Connection timeout in seconds
        
    Returns:
        tuple: (port, is_open)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return (port, result == 0)
    except:
        return (port, False)

def parse_port_range(port_range):
    """
    Parse port range string (e.g., "1-1000" or "80,443,8080")
    
    Args:
        port_range (str): Port range specification
        
    Returns:
        list: List of port numbers
    """
    ports = []
    
    for part in port_range.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return ports

def scan(target, port_range='1-1000', threads=100):
    """
    Scan ports on target host
    
    Args:
        target (str): Target IP or domain
        port_range (str): Port range to scan
        threads (int): Number of concurrent threads
        
    Returns:
        dict: Scan results with open ports
    """
    # Remove http/https if present
    target = target.replace('http://', '').replace('https://', '').split('/')[0]
    
    results = {
        'target': target,
        'open_ports': [],
        'closed_count': 0
    }
    
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(target)
        results['ip'] = ip
        logger.info(f"Resolved {target} to {ip}")
        
        # Parse port range
        ports = parse_port_range(port_range)
        logger.info(f"Scanning {len(ports)} ports on {target}")
        
        print(f"    [*] Scanning {len(ports)} ports... (this may take a while)")
        
        open_count = 0
        
        # Scan ports using thread pool
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port, is_open = future.result()
                
                if is_open:
                    open_count += 1
                    results['open_ports'].append(port)
                    logger.debug(f"Port {port} is open")
                    print(f"    [+] Port {port}/tcp is OPEN")
                else:
                    results['closed_count'] += 1
        
        results['open_ports'].sort()
        logger.info(f"Scan complete: {open_count} open ports found")
        print(f"    [+] Scan complete: {open_count} open port(s) found")
        
    except socket.gaierror:
        logger.error(f"Could not resolve hostname: {target}")
        results['error'] = 'Could not resolve hostname'
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
        results['error'] = str(e)
    
    return results