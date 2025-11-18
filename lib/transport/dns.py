import dns.resolver

def send_dns_query(data: bytes, target: str):
    subdomain = data.decode('ascii') if isinstance(data, bytes) else data
    query_domain = f"{subdomain}.{target}"
    responses = []
    try:
        answers = dns.resolver.resolve(query_domain, 'TXT')
        for rdata in answers:
            txt_data = b''.join(rdata.strings).decode('ascii')
            responses.append(txt_data)
        return responses
    except Exception as e:
        return []
