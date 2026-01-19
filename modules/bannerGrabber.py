"""
Banner Grabbing Module
Grabs service banners from open ports with HTTP/HTTPS support
"""

import socket
import logging
import ssl

logger = logging.getLogger(__name__)

def grab_banner(host, port, timeout=3):
    """
    Grab banner from a specific port
    
    Args:
        host (str): Target host
        port (int): Port number
        timeout (int): Connection timeout
        
    Returns:
        str: Banner text or error message
    """
    try:
        # Special handling for HTTPS (port 443)
        if port == 443:
            context = ssl.create_default_context()
            sock = socket.create_connection((host, port), timeout=timeout)
            ssock = context.wrap_socket(sock, server_hostname=host)

            request = b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
            ssock.send(request)

            banner = ssock.recv(1024).decode('utf-8', errors='ignore').strip()

            ssock.close()
            return banner if banner else 'No HTTPS banner received'

        # Normal TCP banner grabbing for other ports
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            # Some services need a request first (like HTTP)
            try:
                sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                banner = ""

        sock.close()
        return banner if banner else 'No banner received'
        
    except socket.timeout:
        return 'Connection timeout'
    except ssl.SSLError:
        return 'SSL/TLS handshake failed'
    except Exception as e:
        return f'Error: {str(e)}'


def grab(target, port_scan_results):
    """
    Grab banners from all open ports
    
    Args:
        target (str): Target IP or domain
        port_scan_results (dict): Results from port scanner
        
    Returns:
        dict: Banners for each open port
    """
    # Remove http/https if present
    target = target.replace('http://', '').replace('https://', '').split('/')[0]
    
    results = {
        'target': target,
        'banners': {}
    }
    
    if not port_scan_results or 'open_ports' not in port_scan_results:
        logger.warning("No open ports provided for banner grabbing")
        return results
    
    open_ports = port_scan_results.get('open_ports', [])
    
    if not open_ports:
        logger.info("No open ports to grab banners from")
        return results
    
    logger.info(f"Grabbing banners from {len(open_ports)} ports")
    
    for port in open_ports:
        logger.debug(f"Grabbing banner from port {port}")
        banner = grab_banner(target, port)
        results['banners'][port] = banner
        
        # Display banner (truncated for readability)
        banner_preview = banner[:100] + '...' if len(banner) > 100 else banner
        print(f"    [+] Port {port}: {banner_preview}")
    
    return results
