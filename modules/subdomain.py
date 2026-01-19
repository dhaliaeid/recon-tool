"""
Subdomain Enumeration Module
Uses certificate transparency logs (crt.sh) to find subdomains
"""

import requests
import json
import logging

logger = logging.getLogger(__name__)

def enumerate(domain):
    """
    Enumerate subdomains using crt.sh certificate transparency logs
    
    Args:
        domain (str): Target domain name
        
    Returns:
        dict: List of discovered subdomains
    """
    # Remove http/https if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    subdomains = set()
    results = {
        'domain': domain,
        'subdomains': [],
        'count': 0
    }
    
    try:
        logger.debug(f"Querying crt.sh for {domain}")
        
        # Query crt.sh
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle multiple domains in one certificate
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        # Remove wildcards
                        subdomain = subdomain.replace('*.', '')
                        if subdomain and domain in subdomain:
                            subdomains.add(subdomain)
                
                logger.info(f"Found {len(subdomains)} unique subdomains")
                
            except json.JSONDecodeError:
                logger.error("Failed to parse crt.sh response")
                results['error'] = 'Failed to parse response'
        else:
            logger.error(f"crt.sh returned status code {response.status_code}")
            results['error'] = f'HTTP {response.status_code}'
    
    except requests.Timeout:
        logger.error("Request to crt.sh timed out")
        results['error'] = 'Request timeout'
    except Exception as e:
        logger.error(f"Subdomain enumeration failed: {e}")
        results['error'] = str(e)
    
    results['subdomains'] = sorted(list(subdomains))
    results['count'] = len(results['subdomains'])
    
    print(f"    [+] Found {results['count']} subdomains")
    
    return results