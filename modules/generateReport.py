"""
Report Generator Module
Generates HTML reports from reconnaissance results
"""

import logging

logger = logging.getLogger(__name__)

def generate_report(results, output_file):
    """
    Generate HTML report from reconnaissance results
    
    Args:
        results (dict): All reconnaissance results
        output_file (str): Output file path
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {results['target']}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ margin: 0; font-size: 2.5em; }}
        h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .info {{ color: #666; margin-top: 10px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            background: #667eea;
            color: white;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 2px;
        }}
        .port {{
            background: #28a745;
        }}
        .code {{
            background: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .subdomain {{
            background: #e9ecef;
            padding: 8px 12px;
            margin: 5px;
            display: inline-block;
            border-radius: 5px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1> Reconnaissance Report</h1>
        <div class="info">
            <strong>Target:</strong> {results['target']}<br>
            <strong>Scan Date:</strong> {results['timestamp']}
        </div>
    </div>
"""

    # WHOIS Section
    if results.get('whois'):
        whois = results['whois']
        html += """
    <div class="section">
        <h2> WHOIS Information</h2>
"""
        if whois.get('status') == 'success':
            html += f"""
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Domain</td><td>{whois.get('domain', 'N/A')}</td></tr>
"""
            if 'registrar' in whois:
                html += f"<tr><td>Registrar</td><td>{whois['registrar']}</td></tr>"
            if 'created' in whois:
                html += f"<tr><td>Created</td><td>{whois['created']}</td></tr>"
            if 'expires' in whois:
                html += f"<tr><td>Expires</td><td>{whois['expires']}</td></tr>"
            if 'referral_server' in whois:
                html += f"<tr><td>Referral Server</td><td>{whois['referral_server']}</td></tr>"
            
            html += "</table>"
        else:
            html += f"<p>❌ Error: {whois.get('message', 'Unknown error')}</p>"
        
        html += "    </div>\n"

    # DNS Section
    if results.get('dns'):
        dns = results['dns']
        html += """
    <div class="section">
        <h2>DNS Records</h2>
"""
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
            records = dns.get(record_type, [])
            if records:
                html += f"        <h3>{record_type} Records</h3>\n        <ul>\n"
                for record in records:
                    if isinstance(record, dict):
                        html += f"            <li>{record}</li>\n"
                    else:
                        html += f"            <li>{record}</li>\n"
                html += "        </ul>\n"
        
        html += "    </div>\n"

    # Subdomains Section
    if results.get('subdomains'):
        subs = results['subdomains']
        html += f"""
    <div class="section">
        <h2>Subdomains ({subs.get('count', 0)} found)</h2>
"""
        if subs.get('subdomains'):
            for subdomain in subs['subdomains'][:50]:  # Limit display
                html += f'        <span class="subdomain">{subdomain}</span>\n'
            if len(subs['subdomains']) > 50:
                html += f"        <p><em>...and {len(subs['subdomains']) - 50} more</em></p>\n"
        else:
            html += "        <p>No subdomains found</p>\n"
        
        html += "    </div>\n"

    # Port Scan Section
    if results.get('ports'):
        ports = results['ports']
        html += f"""
    <div class="section">
        <h2>Open Ports ({len(ports.get('open_ports', []))}/{ports.get('closed_count', 0) + len(ports.get('open_ports', []))} scanned)</h2>
"""
        if ports.get('ip'):
            html += f"        <p><strong>IP Address:</strong> {ports['ip']}</p>\n"
        
        if ports.get('open_ports'):
            html += "        <table>\n            <tr><th>Port</th><th>State</th></tr>\n"
            for port in ports['open_ports']:
                html += f'            <tr><td><span class="badge port">{port}/tcp</span></td><td>OPEN</td></tr>\n'
            html += "        </table>\n"
        else:
            html += "        <p>No open ports found</p>\n"
        
        html += "    </div>\n"

    # Banners Section
    if results.get('banners'):
        banners = results['banners']
        if banners.get('banners'):
            html += """
    <div class="section">
        <h2>Service Banners</h2>
"""
            for port, banner in banners['banners'].items():
                html += f"""
        <h3>Port {port}</h3>
        <div class="code">{banner}</div>
"""
            html += "    </div>\n"

    # Technologies Section
    if results.get('technologies'):
        tech = results['technologies']
        html += """
    <div class="section">
        <h2>Detected Technologies</h2>
"""
        if tech.get('server'):
            html += f"        <p><strong>Server:</strong> {tech['server']}</p>\n"
        if tech.get('cms'):
            html += f"        <p><strong>CMS:</strong> {tech['cms']}</p>\n"
        
        if tech.get('technologies'):
            html += "        <p><strong>Technologies:</strong></p>\n        <div>\n"
            for t in tech['technologies']:
                html += f'            <span class="badge">{t}</span>\n'
            html += "        </div>\n"
        
        html += "    </div>\n"

    html += """
</body>
</html>"""

    # Write to file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        logger.info(f"Report generated: {output_file}")
    except Exception as e:
        logger.error(f"Failed to write report: {e}")
        raise