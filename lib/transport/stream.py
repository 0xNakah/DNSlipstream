# lib/transport/dnsclient.py
import queue
import threading
import uuid
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
import io

from lib.transport.encoding import encode
from lib.transport.dns_query import send_dns_query
from lib.transport.poller import poll_read

# Global packet queue for received data
packet_queue = queue.Queue()


class DNSStream:
    """DNS-based transport stream implementing read/write interface."""
    
    def __init__(self, target_domain: str, encryption_key: str):
        """
        Initialize DNS stream.
        
        Args:
            target_domain: The domain to use for DNS queries
            encryption_key: Hex-encoded encryption key
        """
        self.target_domain = target_domain
        self.encryption_key = encryption_key
        
        # Generate a unique client GUID (16 bytes like xid in Go)
        self.client_guid = uuid.uuid4().bytes
        
        # Start polling thread to read data from DNS server
        self._start_polling()
    
    def _start_polling(self):
        """Start background thread to poll for incoming data."""
        poll_thread = threading.Thread(
            target=poll_read,
            args=(self,),
            daemon=True
        )
        poll_thread.start()
    
    def read(self, size: int = -1) -> bytes:
        """
        Read data from the DNS stream.
        
        Args:
            size: Maximum number of bytes to read (ignored, returns full packet)
            
        Returns:
            bytes: Data received from the stream
        """
        # Wait for a packet in the queue (blocking)
        packet = packet_queue.get()
        return packet
    
    def write(self, data: bytes) -> int:
        """
        Write data to the DNS stream.
        
        Args:
            data: Bytes to send through DNS
            
        Returns:
            int: Number of bytes written
            
        Raises:
            IOError: If unable to send packets
        """
        # Encode the data into DNS packets
        init_packet, data_packets = encode(
            data,
            is_client=True,
            encryption_key=self.encryption_key,
            target_domain=self.target_domain,
            client_guid=self.client_guid
        )
        
        # Send the init packet to inform server we will send data
        try:
            send_dns_query(init_packet.encode(), self.target_domain)
        except Exception as e:
            print(f"Unable to send init packet: {e}")
            raise IOError("Connection closed") from e
        
        # Create a thread pool to asynchronously send DNS packets (8 workers)
        with ThreadPoolExecutor(max_workers=8) as executor:
            # Submit all data packets to the pool
            futures = []
            for packet in data_packets:
                future = executor.submit(self._send_packet, packet)
                futures.append(future)
            
            # Wait for all packets to be sent
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    print(f"Failed to send data packet: {e}")
        
        return len(data)
    
    def _send_packet(self, packet: str):
        """
        Send a single DNS packet.
        
        Args:
            packet: The packet string to send
        """
        try:
            send_dns_query(packet.encode(), self.target_domain)
        except Exception as e:
            print(f"Failed to send data packet: {e}")
            raise
    
    def close(self):
        """Close the DNS stream."""
        # Cleanup if needed
        pass
    
    def readable(self) -> bool:
        """Returns True if stream is readable."""
        return True
    
    def writable(self) -> bool:
        """Returns True if stream is writable."""
        return True


def dns_stream(target_domain: str, encryption_key: str) -> DNSStream:
    """
    Factory function to create a DNS stream.
    
    Args:
        target_domain: The domain to use for DNS queries
        encryption_key: Hex-encoded encryption key
        
    Returns:
        DNSStream: Configured DNS stream instance
    """
    return DNSStream(target_domain, encryption_key)
