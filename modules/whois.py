"""
WHOIS Lookup Module
"""

import socket
import logging

logger = logging.getLogger(__name__)

def lookup(domain):
    """
    Perform WHOIS lookup on a domain
    
    Args:
        domain (str): Target domain name
        
    Returns:
        dict: WHOIS information or error message
    """
    try:
        # Remove http/https if present
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Connect to WHOIS server
        whois_server = "whois.iana.org"
        port = 43
        
        logger.debug(f"Connecting to WHOIS server: {whois_server}")
        
        # Create socket and query
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((whois_server, port))
        s.send(f"{domain}\r\n".encode())
        
        # Receive response
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        response_text = response.decode('utf-8', errors='ignore')
        
        # Parse important information
        result = {
            'raw': response_text,
            'domain': domain,
            'status': 'success'
        }
        
        # Extract key fields
        lines = response_text.split('\n')
        for line in lines:
            if 'refer:' in line.lower():
                result['referral_server'] = line.split(':', 1)[1].strip()
            elif 'registrar:' in line.lower():
                result['registrar'] = line.split(':', 1)[1].strip()
            elif 'creation date:' in line.lower() or 'created:' in line.lower():
                result['created'] = line.split(':', 1)[1].strip()
            elif 'expir' in line.lower():
                result['expires'] = line.split(':', 1)[1].strip()
        
        logger.info(f"WHOIS lookup successful for {domain}")
        print(f"    [+] WHOIS lookup completed")
        
        return result
        
    except socket.timeout:
        logger.error(f"WHOIS lookup timed out for {domain}")
        return {'status': 'error', 'message': 'Connection timeout', 'domain': domain}
    except Exception as e:
        logger.error(f"WHOIS lookup failed: {e}")
        return {'status': 'error', 'message': str(e), 'domain': domain}