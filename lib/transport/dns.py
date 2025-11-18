# lib/transport/dns.py
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype

def send_dns_query(data: bytes, target: str):
    """Send DNS TXT query with proper port support."""
    subdomain = data.decode('ascii') if isinstance(data, bytes) else data
    query_domain = f"{subdomain}.{target}"
    responses = []
    
    try:
        # Determine DNS server and port based on target
        if target.endswith('.local') or target == 'localhost' or 'localhost' in target:
            # Local testing mode
            dns_server = '127.0.0.1'
            dns_port = 53
        else:
            # Production mode - use public DNS
            dns_server = '8.8.8.8'
            dns_port = 53
        
        # Create DNS query message
        query = dns.message.make_query(query_domain, dns.rdatatype.TXT)
        
        # Send query with explicit port
        response = dns.query.udp(query, dns_server, port=dns_port, timeout=5)
        
        # Extract TXT records from response
        for answer in response.answer:
            for item in answer:
                if item.rdtype == dns.rdatatype.TXT:
                    txt_data = b''.join(item.strings).decode('ascii')
                    responses.append(txt_data)
        
        return responses
        
    except Exception as e:
        return []
