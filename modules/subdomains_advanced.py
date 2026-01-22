"""
Advanced Subdomain Enumeration Module
Uses multiple passive sources (crt.sh, HackerTarget, ThreatCrowd, VirusTotal API)
"""

import requests
import json
import logging
import time

logger = logging.getLogger(__name__)


def query_crtsh(domain):
    """
    Query crt.sh certificate transparency logs
    
    Args:
        domain (str): Target domain
        
    Returns:
        set: Discovered subdomains
    """
    subdomains = set()
    
    try:
        logger.debug(f"Querying crt.sh for {domain}")
        print(f"    [*] Querying crt.sh...")
        
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
                
                logger.info(f"crt.sh found {len(subdomains)} subdomains")
                print(f"    [+] crt.sh: {len(subdomains)} subdomains")
                
            except json.JSONDecodeError:
                logger.error("Failed to parse crt.sh response")
        else:
            logger.warning(f"crt.sh returned status code {response.status_code}")
    
    except requests.Timeout:
        logger.error("Request to crt.sh timed out")
    except Exception as e:
        logger.error(f"crt.sh query failed: {e}")
    
    return subdomains


def query_hackertarget(domain):
    """
    Query HackerTarget API
    
    Args:
        domain (str): Target domain
        
    Returns:
        set: Discovered subdomains
    """
    subdomains = set()
    
    try:
        logger.debug(f"Querying HackerTarget for {domain}")
        print(f"    [*] Querying HackerTarget...")
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=20)
        
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            
            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip().lower()
                    if subdomain and domain in subdomain:
                        subdomains.add(subdomain)
            
            logger.info(f"HackerTarget found {len(subdomains)} subdomains")
            print(f"    [+] HackerTarget: {len(subdomains)} subdomains")
        else:
            logger.warning(f"HackerTarget returned status code {response.status_code}")
    
    except requests.Timeout:
        logger.error("Request to HackerTarget timed out")
    except Exception as e:
        logger.error(f"HackerTarget query failed: {e}")
    
    return subdomains


def query_threatcrowd(domain):
    """
    Query ThreatCrowd API
    
    Args:
        domain (str): Target domain
        
    Returns:
        set: Discovered subdomains
    """
    subdomains = set()
    
    try:
        logger.debug(f"Querying ThreatCrowd for {domain}")
        print(f"    [*] Querying ThreatCrowd...")
        
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        response = requests.get(url, timeout=20)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        subdomain = subdomain.strip().lower()
                        if subdomain and domain in subdomain:
                            subdomains.add(subdomain)
                
                logger.info(f"ThreatCrowd found {len(subdomains)} subdomains")
                print(f"    [+] ThreatCrowd: {len(subdomains)} subdomains")
                
            except json.JSONDecodeError:
                logger.error("Failed to parse ThreatCrowd response")
        else:
            logger.warning(f"ThreatCrowd returned status code {response.status_code}")
    
    except requests.Timeout:
        logger.error("Request to ThreatCrowd timed out")
    except Exception as e:
        logger.error(f"ThreatCrowd query failed: {e}")
    
    return subdomains


def query_alienvault(domain):
    """
    Query AlienVault OTX API
    
    Args:
        domain (str): Target domain
        
    Returns:
        set: Discovered subdomains
    """
    subdomains = set()
    
    try:
        logger.debug(f"Querying AlienVault OTX for {domain}")
        print(f"    [*] Querying AlienVault OTX...")
        
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(url, timeout=20)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                if 'passive_dns' in data:
                    for entry in data['passive_dns']:
                        hostname = entry.get('hostname', '').strip().lower()
                        if hostname and domain in hostname:
                            subdomains.add(hostname)
                
                logger.info(f"AlienVault OTX found {len(subdomains)} subdomains")
                print(f"    [+] AlienVault OTX: {len(subdomains)} subdomains")
                
            except json.JSONDecodeError:
                logger.error("Failed to parse AlienVault response")
        else:
            logger.warning(f"AlienVault returned status code {response.status_code}")
    
    except requests.Timeout:
        logger.error("Request to AlienVault timed out")
    except Exception as e:
        logger.error(f"AlienVault query failed: {e}")
    
    return subdomains


def query_urlscan(domain):
    """
    Query URLScan.io API
    
    Args:
        domain (str): Target domain
        
    Returns:
        set: Discovered subdomains
    """
    subdomains = set()
    
    try:
        logger.debug(f"Querying URLScan.io for {domain}")
        print(f"    [*] Querying URLScan.io...")
        
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        response = requests.get(url, timeout=20)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                if 'results' in data:
                    for result in data['results']:
                        page_domain = result.get('page', {}).get('domain', '').strip().lower()
                        if page_domain and domain in page_domain:
                            subdomains.add(page_domain)
                        
                        task_domain = result.get('task', {}).get('domain', '').strip().lower()
                        if task_domain and domain in task_domain:
                            subdomains.add(task_domain)
                
                logger.info(f"URLScan.io found {len(subdomains)} subdomains")
                print(f"    [+] URLScan.io: {len(subdomains)} subdomains")
                
            except json.JSONDecodeError:
                logger.error("Failed to parse URLScan response")
        else:
            logger.warning(f"URLScan.io returned status code {response.status_code}")
    
    except requests.Timeout:
        logger.error("Request to URLScan.io timed out")
    except Exception as e:
        logger.error(f"URLScan.io query failed: {e}")
    
    return subdomains


def enumerate(domain):
    """
    Enumerate subdomains using multiple passive sources
    
    Args:
        domain (str): Target domain name
        
    Returns:
        dict: List of discovered subdomains with source information
    """
    # Remove http/https if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    all_subdomains = set()
    sources_used = []
    
    results = {
        'domain': domain,
        'subdomains': [],
        'count': 0,
        'sources': {}
    }
    
    print(f"\n    [*] Starting advanced subdomain enumeration...")
    print(f"    [*] Target: {domain}")
    print(f"    [*] Using multiple passive sources...\n")
    
    # Query all sources
    sources = {
        'crt.sh': query_crtsh,
        'HackerTarget': query_hackertarget,
        'ThreatCrowd': query_threatcrowd,
        'AlienVault OTX': query_alienvault,
        'URLScan.io': query_urlscan
    }
    
    for source_name, query_func in sources.items():
        try:
            subs = query_func(domain)
            if subs:
                all_subdomains.update(subs)
                results['sources'][source_name] = len(subs)
                sources_used.append(source_name)
            
            # Rate limiting - be nice to APIs
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"Error querying {source_name}: {e}")
            results['sources'][source_name] = 0
    
    # Compile results
    results['subdomains'] = sorted(list(all_subdomains))
    results['count'] = len(results['subdomains'])
    results['sources_used'] = sources_used
    
    logger.info(f"Total unique subdomains found: {results['count']} from {len(sources_used)} sources")
    
    print(f"\n    [+] Enumeration complete!")
    print(f"    [+] Total unique subdomains: {results['count']}")
    print(f"    [+] Sources used: {', '.join(sources_used)}")
    
    return results