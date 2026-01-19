#!/usr/bin/env python3
"""
Custom Reconnaissance Tool
A modular penetration testing reconnaissance tool
"""

import argparse
import sys
import logging
from datetime import datetime
from modules import whois, dnsEnum, subdomain, portScan, bannerGrabber, techDetector, generateReport

# Setup logging
def setup_logging(verbosity):
    levels = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG
    }
    level = levels.get(verbosity, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def main():
    parser = argparse.ArgumentParser(
        description='Custom Reconnaissance Tool for Penetration Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py --target example.com --whois
  python recon.py --target example.com --dns --subdomains
  python recon.py --target example.com --all -vv
  python recon.py --target 192.168.1.1 --port-scan --banner
        """
    )
    
    # Required arguments
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP address')
    
    # Passive recon modules
    parser.add_argument('--whois', action='store_true', help='Perform WHOIS lookup')
    parser.add_argument('--dns', action='store_true', help='Enumerate DNS records')
    parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains')
    
    # Active recon modules
    parser.add_argument('--port-scan', action='store_true', help='Perform port scanning')
    parser.add_argument('--banner', action='store_true', help='Grab service banners')
    parser.add_argument('--tech', action='store_true', help='Detect web technologies')
    
    # Convenience options
    parser.add_argument('--all', action='store_true', help='Run all reconnaissance modules')
    parser.add_argument('--passive', action='store_true', help='Run only passive recon modules')
    
    # Output and verbosity
    parser.add_argument('-o', '--output', help='Output report file (default: report.html)')
    parser.add_argument('-v', '--verbose', action='count', default=0, 
                        help='Increase verbosity (-v, -vv, -vvv)')
    
    # Port scan options
    parser.add_argument('--ports', default='1-1000', help='Port range to scan (default: 1-1000)')
    
    args = parser.parse_args()
    
    # Setup logging based on verbosity
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Storage for results
    results = {
        'target': args.target,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'whois': None,
        'dns': None,
        'subdomains': None,
        'ports': None,
        'banners': None,
        'technologies': None
    }
    
    print(f"\n{'='*60}")
    print(f"  Custom Reconnaissance Tool")
    print(f"  Target: {args.target}")
    print(f"  Time: {results['timestamp']}")
    print(f"{'='*60}\n")
    
    # Determine which modules to run
    run_whois = args.whois or args.all or args.passive
    run_dns = args.dns or args.all or args.passive
    run_subdomains = args.subdomains or args.all or args.passive
    run_port_scan = args.port_scan or args.all
    run_banner = args.banner or args.all
    run_tech = args.tech or args.all
    
    # Execute passive recon modules
    if run_whois:
        logger.info("Starting WHOIS lookup...")
        print("[*] Running WHOIS lookup...")
        try:
            results['whois'] = whois.lookup(args.target)
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            results['whois'] = {'status': 'error', 'message': str(e), 'domain': args.target}
    
    if run_dns:
        logger.info("Starting DNS enumeration...")
        print("[*] Running DNS enumeration...")
        results['dns'] = dnsEnum.enumerate(args.target)
    
    if run_subdomains:
        logger.info("Starting subdomain enumeration...")
        print("[*] Running subdomain enumeration...")
        results['subdomains'] = subdomain.enumerate(args.target)
    
    # Execute active recon modules
    if run_port_scan:
        logger.info("Starting port scan...")
        print("[*] Running port scan...")
        results['ports'] = portScan.scan(args.target, args.ports)
    
    if run_banner:
        logger.info("Starting banner grabbing...")
        print("[*] Running banner grabbing...")
        # Only grab banners if we have open ports
        if results['ports']:
            results['banners'] = bannerGrabber.grab(args.target, results['ports'])
        else:
            print("    [!] No open ports found. Skipping banner grabbing.")
    
    if run_tech:
        logger.info("Starting technology detection...")
        print("[*] Running technology detection...")
        results['technologies'] = techDetector.detect(args.target)
    
    # Generate report
    output_file = args.output or f"report_{args.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    print(f"\n[*] Generating report: {output_file}")
    generateReport.generate_report(results, output_file)
    print(f"[+] Report saved to: {output_file}")
    
    print(f"\n{'='*60}")
    print("  Reconnaissance Complete!")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)