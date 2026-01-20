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

def display_whois_results(whois_data):
    """
    Display WHOIS results in CLI
    
    Args:
        whois_data (dict): WHOIS lookup results
    """
    print("\n" + "=" * 70)
    print("  WHOIS LOOKUP RESULTS")
    print("=" * 70)
    
    if whois_data.get('status') == 'error':
        print(f"\n❌ Error: {whois_data.get('message', 'Unknown error')}")
        print(f"   Domain: {whois_data['domain']}")
        return
    
    print(f"\nDomain Information:")
    print(f"   Domain: {whois_data.get('domain', 'N/A')}")
    
    if 'registrar' in whois_data:
        print(f"   Registrar: {whois_data['registrar']}")
    
    if 'created' in whois_data:
        print(f"   Created: {whois_data['created']}")
    
    if 'updated' in whois_data:
        print(f"   Updated: {whois_data['updated']}")
    
    if 'expires' in whois_data:
        print(f"   Expires: {whois_data['expires']}")
    
    if 'referral_server' in whois_data:
        print(f"   Referral Server: {whois_data['referral_server']}")
    
    print(f"\nRaw WHOIS Response:")
    print("-" * 70)
    print(whois_data.get('raw', 'No raw data available'))
    print("-" * 70)


def display_dns_results(dns_data):
    """
    Display DNS results in CLI
    
    Args:
        dns_data (dict): DNS enumeration results
    """
    print("\n" + "=" * 70)
    print("  DNS RECORDS")
    print("=" * 70)
    
    if dns_data.get('error'):
        print(f"\n❌ Error: {dns_data['error']}")
        return
    
    for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
        records = dns_data.get(record_type, [])
        if records:
            print(f"\n {record_type} Records:")
            for record in records:
                if isinstance(record, dict):
                    print(f"   • {record}")
                else:
                    print(f"   • {record}")


def display_subdomain_results(subdomain_data):
    """
    Display subdomain results in CLI
    
    Args:
        subdomain_data (dict): Subdomain enumeration results
    """
    print("\n" + "=" * 70)
    print(f"  SUBDOMAINS ({subdomain_data.get('count', 0)} found)")
    print("=" * 70)
    
    if subdomain_data.get('error'):
        print(f"\n❌ Error: {subdomain_data['error']}")
        return
    
    if subdomain_data.get('subdomains'):
        print()
        for subdomain in subdomain_data['subdomains']:
            print(f"   • {subdomain}")
    else:
        print("\nNo subdomains found")


def display_port_results(port_data):
    """
    Display port scan results in CLI
    
    Args:
        port_data (dict): Port scan results
    """
    print("\n" + "=" * 70)
    print(f"  OPEN PORTS ({len(port_data.get('open_ports', []))} found)")
    print("=" * 70)
    
    if port_data.get('error'):
        print(f"\n❌ Error: {port_data['error']}")
        return
    
    if port_data.get('ip'):
        print(f"\n IP Address: {port_data['ip']}")
    
    if port_data.get('open_ports'):
        print(f"\nOpen Ports:")
        for port in port_data['open_ports']:
            print(f"   • Port {port}/tcp - OPEN")
    else:
        print("\nNo open ports found")


def display_banner_results(banner_data):
    """
    Display banner grab results in CLI
    
    Args:
        banner_data (dict): Banner grabbing results
    """
    if not banner_data.get('banners'):
        return
    
    print("\n" + "=" * 70)
    print("  SERVICE BANNERS")
    print("=" * 70)
    
    for port, banner in banner_data['banners'].items():
        print(f"\nPort {port}:")
        print("-" * 70)
        print(f"{banner}")
        print("-" * 70)


def display_tech_results(tech_data):
    """
    Display technology detection results in CLI
    
    Args:
        tech_data (dict): Technology detection results
    """
    print("\n" + "=" * 70)
    print("  DETECTED TECHNOLOGIES")
    print("=" * 70)
    
    if tech_data.get('error'):
        print(f"\n❌ Error: {tech_data['error']}")
        return
    
    if tech_data.get('server'):
        print(f"\nServer: {tech_data['server']}")
    
    if tech_data.get('cms'):
        print(f" CMS: {tech_data['cms']}")
    
    if tech_data.get('technologies'):
        print(f"\nTechnologies:")
        for tech in tech_data['technologies']:
            print(f"   • {tech}")


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
    parser.add_argument('-o', '--output', help='Output report file (e.g., report.html or report.txt)')
    parser.add_argument('-v', '--verbose', action='count', default=0, 
                        help='Increase verbosity (-v, -vv, -vvv)')
    parser.add_argument('--format', choices=['html', 'txt'], default='html',
                        help='Report format (default: html)')
    parser.add_argument('--no-report', action='store_true',
                        help='Skip report generation (only display in CLI)')
    
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
    
    # Display ASCII banner
    banner = """
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗     ████████╗ ██████╗  ██████╗ ██╗     
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║     ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║        ██║   ██║   ██║██║   ██║██║     
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║        ██║   ██║   ██║██║   ██║██║     
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║        ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
    Recon-Tool | Modular Reconnaissance Framework
    Author: Dalia Ibrahim
    Purpose: Pentesting & Bug Bounty Recon
    """
    print(banner)
    print(f"    Target: {args.target}")
    print(f"    Time: {results['timestamp']}")
    print(f"    {'─'*58}\n")
    
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
            display_whois_results(results['whois'])
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            results['whois'] = {'status': 'error', 'message': str(e), 'domain': args.target}
    
    if run_dns:
        logger.info("Starting DNS enumeration...")
        print("\n[*] Running DNS enumeration...")
        results['dns'] = dnsEnum.enumerate(args.target)
        display_dns_results(results['dns'])
    
    if run_subdomains:
        logger.info("Starting subdomain enumeration...")
        print("\n[*] Running subdomain enumeration...")
        results['subdomains'] = subdomain.enumerate(args.target)
        display_subdomain_results(results['subdomains'])
    
    # Execute active recon modules
    if run_port_scan:
        logger.info("Starting port scan...")
        print("\n[*] Running port scan...")
        results['ports'] = portScan.scan(args.target, args.ports)
        display_port_results(results['ports'])
    
    if run_banner:
        logger.info("Starting banner grabbing...")
        print("\n[*] Running banner grabbing...")
        # Only grab banners if we have open ports
        if results['ports']:
            results['banners'] = bannerGrabber.grab(args.target, results['ports'])
            display_banner_results(results['banners'])
        else:
            print("    [!] No open ports found. Skipping banner grabbing.")
    
    if run_tech:
        logger.info("Starting technology detection...")
        print("\n[*] Running technology detection...")
        results['technologies'] = techDetector.detect(args.target)
        display_tech_results(results['technologies'])
    
    # Generate report (unless --no-report is specified)
    if not args.no_report:
        if not args.output:
            # Auto-generate filename based on format
            ext = 'html' if args.format == 'html' else 'txt'
            output_file = f"report_{args.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        else:
            output_file = args.output
        
        print(f"\n[*] Generating report: {output_file}")
        generateReport.generate_report(results, output_file)
        print(f"[+] Report saved to: {output_file}")
    else:
        print(f"\n[*] Report generation skipped (--no-report flag used)")
    
    print(f"\n    {'─'*58}")
    print("    🎯 Reconnaissance Complete!")
    print(f"    {'─'*58}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)