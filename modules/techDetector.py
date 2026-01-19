"""
Technology Detection Module
Detects web technologies using HTTP headers and response analysis
"""

import requests
import re
import logging
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

def detect(target):
    """
    Detect web technologies on target
    
    Args:
        target (str): Target URL or domain
        
    Returns:
        dict: Detected technologies
    """
    # Ensure URL has protocol
    if not target.startswith('http'):
        target = f'http://{target}'
    
    results = {
        'target': target,
        'technologies': [],
        'server': None,
        'headers': {},
        'cms': None
    }
    
    try:
        logger.debug(f"Fetching {target}")
        
        # Make request
        response = requests.get(target, timeout=10, allow_redirects=True, verify=False)
        
        # Store headers
        results['headers'] = dict(response.headers)
        
        # Detect server
        server = response.headers.get('Server', 'Unknown')
        results['server'] = server
        logger.info(f"Detected server: {server}")
        
        # Detect technologies from headers
        if 'X-Powered-By' in response.headers:
            tech = response.headers['X-Powered-By']
            results['technologies'].append(f"X-Powered-By: {tech}")
        
        # Get page content
        content = response.text
        
        # Detect CMS and frameworks
        cms_signatures = {
            'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
            'Joomla': [r'Joomla', r'/components/com_'],
            'Drupal': [r'Drupal', r'sites/default/files'],
            'Magento': [r'Magento', r'skin/frontend'],
            'Django': [r'csrfmiddlewaretoken'],
            'Laravel': [r'laravel', r'laravel_session'],
            'React': [r'react', r'__REACT'],
            'Angular': [r'ng-app', r'angular'],
            'Vue.js': [r'Vue', r'v-if', r'v-for'],
            'jQuery': [r'jquery']
        }
        
        for cms, patterns in cms_signatures.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if not results['cms']:
                        results['cms'] = cms
                    if cms not in results['technologies']:
                        results['technologies'].append(cms)
                    break
        
        # Detect from meta tags
        meta_generator = re.search(r'<meta name="generator" content="([^"]+)"', content, re.IGNORECASE)
        if meta_generator:
            results['technologies'].append(f"Generator: {meta_generator.group(1)}")
        
        logger.info(f"Detected {len(results['technologies'])} technologies")
        print(f"    [+] Server: {server}")
        if results['cms']:
            print(f"    [+] CMS: {results['cms']}")
        print(f"    [+] Technologies found: {len(results['technologies'])}")
        
    except requests.Timeout:
        logger.error("Request timed out")
        results['error'] = 'Request timeout'
    except requests.RequestException as e:
        logger.error(f"Failed to fetch target: {e}")
        results['error'] = str(e)
    except Exception as e:
        logger.error(f"Technology detection failed: {e}")
        results['error'] = str(e)
    
    return results