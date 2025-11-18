# lib/transport/dns_query.py
import dns.resolver
from typing import List


def send_dns_query(data: bytes, target: str) -> List[str]:
    """
    Send a DNS TXT query to tunnel data.
    
    Args:
        data: Data to send (will be used as subdomain)
        target: Target domain
        
    Returns:
        List of TXT record responses
        
    Raises:
        Exception: If DNS query fails
    """
    # Decode bytes to string for the subdomain
    subdomain = data.decode('ascii') if isinstance(data, bytes) else data
    
    # Construct the full query domain
    query_domain = f"{subdomain}.{target}"
    
    try:
        # Use TXT requests to tunnel data
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(query_domain, 'TXT')
        
        # Extract TXT record strings
        responses = []
        for rdata in answers:
            # TXT records are returned as lists of byte strings
            # Join them and decode
            txt_data = b''.join(rdata.strings).decode('ascii')
            responses.append(txt_data)
        
        return responses
        
    except dns.resolver.NXDOMAIN:
        raise Exception(f"Domain not found: {query_domain}")
    except dns.resolver.NoAnswer:
        raise Exception(f"No TXT records found for: {query_domain}")
    except dns.resolver.Timeout:
        raise Exception(f"DNS query timeout for: {query_domain}")
    except Exception as e:
        raise Exception(f"DNS query failed: {e}")
