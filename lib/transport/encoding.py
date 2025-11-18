# lib/transport/encoding.py
import binascii
from typing import Tuple, List, Optional

from lib.crypto.symetric import seal, open_sealed
from lib.protocol import chacomm_pb2
from lib.spliting.split import split, splits


# Global variables for chunk management
_chunk_map = {}  # {chunk_id: {chunk_num: data}}
_sessions = {}   # {chunk_id: ChunkStart}
_current_chunk = 0


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
    except (binascii.Error, ValueError) as e:
        print(f"Invalid packet: {e}")
        return None, False
    
    # Check if the packet is big enough to fit the nonce (24 bytes)
    if len(data_packet_raw) <= 24:
        print("Received packet is too small!")
        return None, False
    
    # Extract nonce (first 24 bytes) and ciphertext (rest)
    nonce = data_packet_raw[:24]
    ciphertext = data_packet_raw[24:]
    
    # Authenticate and decrypt the packet
    output, valid = open_sealed(ciphertext, nonce, encryption_key)
    
    # Raise an error if the message is invalid
    if not valid:
        print("Received invalid/corrupted packet.")
        return None, False
    
    # Parse the "Message" part of the Protocol buffer packet
    message = chacomm_pb2.Message()
    try:
        message.ParseFromString(output)
    except Exception as e:
        print(f"Failed to parse message packet: {e}")
        return None, False
    
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
        if chunk_id in _sessions:
            # Fill the chunk_map with the data from the message
            chunk_num = message.chunkdata.chunknum
            _chunk_map[chunk_id][chunk_num] = message.chunkdata.packet
            
            # Check if we have successfully received all the packets
            expected_size = _sessions[chunk_id].chunksize
            if len(_chunk_map[chunk_id]) == expected_size:
                # Rebuild the final data in order
                chunk_buffer = bytearray()
                
                for i in range(expected_size):
                    chunk_buffer.extend(_chunk_map[chunk_id][i])
                
                # Free some memory
                del _chunk_map[chunk_id]
                del _sessions[chunk_id]
                
                # Return the complete data
                return bytes(chunk_buffer), True
    
    return None, False


def dns_marshal(pb_message: chacomm_pb2.Message, encryption_key: str, is_request: bool) -> str:
    """
    Marshal a protobuf message into an encrypted DNS-compatible format.
    
    Args:
        pb_message: Protocol buffer message to marshal
        encryption_key: Hex-encoded encryption key
        is_request: True if this is a DNS request (requires subdomain splitting)
        
    Returns:
        Hex-encoded encrypted packet, split for DNS if is_request=True
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
    
    # If this is a DNS Request, subdomains cannot be longer than 63 chars
    # We need to split the packet, then join it using "."
    if is_request:
        packet_hex = '.'.join(splits(packet_hex, 63))
    
    return packet_hex


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
    for chunk_num, packet_data in enumerate(packets):
        # Generate the "data" packet, containing the current chunk information and data
        data_message = chacomm_pb2.Message(
            clientguid=client_guid,
            chunkdata=chacomm_pb2.ChunkData(
                chunkid=_current_chunk,
                chunknum=chunk_num,
                packet=packet_data
            )
        )
        
        # Transform the protobuf packet into an encrypted DNS packet
        data_packet = dns_marshal(data_message, encryption_key, is_request)
        data_packets.append(data_packet)
    
    return init_packet, data_packets
