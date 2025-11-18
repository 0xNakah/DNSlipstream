# lib/transport/encoder.py
from typing import List, Tuple

from lib.protocol import chacomm_pb2
from lib.spliting.split import split
from lib.transport.marshaller import dns_marshal


# Global counter for chunk identifiers
_current_chunk = 0


def encode(payload: bytes, is_request: bool, encryption_key: str, 
           target_domain: str, client_guid: bytes) -> Tuple[str, List[str]]:
    """
    Encode payload into DNS packets with chunking support.
    
    Args:
        payload: Raw bytes to send
        is_request: True if this is a DNS request
        encryption_key: Hex-encoded encryption key
        target_domain: Target domain for DNS queries
        client_guid: Client GUID (16 bytes)
        
    Returns:
        Tuple of (init_packet, data_packets_list)
    """
    global _current_chunk
    
    # Chunk the packets so it fits the DNS max length (253)
    # Calculate max chunk size: (240/2) - domain_len - guid_len - (24*2 for nonce hex)
    max_chunk_size = (240 // 2) - len(target_domain) - len(client_guid) - (24 * 2)
    packets = split(payload, max_chunk_size)
    
    # Increment the current chunk identifier
    _current_chunk += 1
    
    # Generate the init packet, containing information about the number of chunks
    init_message = chacomm_pb2.Message(
        clientguid=client_guid,
        chunkstart=chacomm_pb2.ChunkStart(
            chunkid=_current_chunk,
            chunksize=len(packets)
        )
    )
    
    # Transform the protobuf packet into an encrypted DNS packet
    init_packet = dns_marshal(init_message, encryption_key, is_request)
    
    # List to store all data packets
    data_packets = []
    
    # Iterate over every chunk
    for chunk_id, packet in enumerate(packets):
        # Generate the "data" packet, containing the current chunk information and data
        data_message = chacomm_pb2.Message(
            clientguid=client_guid,
            chunkdata=chacomm_pb2.ChunkData(
                chunkid=_current_chunk,
                chunknum=chunk_id,
                packet=packet
            )
        )
        
        # Transform the protobuf packet into an encrypted DNS packet
        data_packet = dns_marshal(data_message, encryption_key, is_request)
        data_packets.append(data_packet)
    
    return init_packet, data_packets


def get_current_chunk() -> int:
    """Get the current chunk counter value."""
    return _current_chunk


def reset_chunk_counter():
    """Reset the chunk counter (useful for testing)."""
    global _current_chunk
    _current_chunk = 0
