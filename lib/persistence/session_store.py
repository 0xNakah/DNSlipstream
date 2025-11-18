# lib/persistence/session_store.py
"""
Session persistence storage for DNSlipstream server.
Saves and restores all active sessions across server restarts.
"""

import json
import os
import time
import pickle
from pathlib import Path


class SessionStore:
    """Persistent storage for server sessions."""
    
    def __init__(self, storage_dir=None):
        """
        Initialize session store.
        
        Args:
            storage_dir: Directory to store session data
        """
        if storage_dir is None:
            storage_dir = os.path.join(os.path.expanduser('~'), '.dnslipstream')
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.sessions_file = self.storage_dir / 'sessions.json'
        self.buffers_file = self.storage_dir / 'buffers.pkl'
        self.queues_file = self.storage_dir / 'queues.pkl'
    
    def save_sessions(self, sessions_map, console_buffer, packet_queue):
        """
        Save all sessions to disk.
        
        Args:
            sessions_map: Dict of client_guid -> ClientInfo
            console_buffer: Dict of client_guid -> buffer data
            packet_queue: Dict of client_guid -> queued packets
        """
        try:
            # Serialize session metadata
            sessions_data = {}
            for client_guid, session in sessions_map.items():
                sessions_data[client_guid] = {
                    'hostname': session.hostname,
                    'heartbeat': session.heartbeat,
                    'last_seen': time.time() - session.heartbeat,
                }
            
            # Write sessions metadata
            with open(self.sessions_file, 'w') as f:
                json.dump(sessions_data, f, indent=2)
            
            # Serialize console buffers (pickle for complex data)
            with open(self.buffers_file, 'wb') as f:
                pickle.dump(dict(console_buffer), f)
            
            # Serialize packet queues
            with open(self.queues_file, 'wb') as f:
                pickle.dump(dict(packet_queue), f)
            
            return True, f"Saved {len(sessions_map)} sessions"
        
        except Exception as e:
            return False, f"Failed to save sessions: {e}"
    
    def load_sessions(self):
        """
        Load all sessions from disk.
        
        Returns:
            Tuple of (sessions_data, console_buffer, packet_queue)
        """
        sessions_data = {}
        console_buffer = {}
        packet_queue = {}
        
        try:
            # Load session metadata
            if self.sessions_file.exists():
                with open(self.sessions_file, 'r') as f:
                    sessions_data = json.load(f)
            
            # Load console buffers
            if self.buffers_file.exists():
                with open(self.buffers_file, 'rb') as f:
                    console_buffer = pickle.load(f)
            
            # Load packet queues
            if self.queues_file.exists():
                with open(self.queues_file, 'rb') as f:
                    packet_queue = pickle.load(f)
            
            return sessions_data, console_buffer, packet_queue
        
        except Exception as e:
            print(f"[-] Error loading sessions: {e}")
            return {}, {}, {}
    
    def clear_sessions(self):
        """Clear all stored session data."""
        try:
            if self.sessions_file.exists():
                self.sessions_file.unlink()
            if self.buffers_file.exists():
                self.buffers_file.unlink()
            if self.queues_file.exists():
                self.queues_file.unlink()
            return True
        except Exception as e:
            print(f"[-] Error clearing sessions: {e}")
            return False
    
    def auto_save_loop(self, get_sessions_func, interval=30):
        """
        Automatically save sessions at regular intervals.
        
        Args:
            get_sessions_func: Function that returns (sessions_map, console_buffer, packet_queue)
            interval: Save interval in seconds
        """
        import threading
        
        def save_worker():
            while True:
                time.sleep(interval)
                try:
                    sessions_map, console_buffer, packet_queue = get_sessions_func()
                    if sessions_map:  # Only save if there are active sessions
                        success, msg = self.save_sessions(sessions_map, console_buffer, packet_queue)
                except Exception as e:
                    print(f"\r[-] Auto-save error: {e}", end='')
                    print(f"\r\n[-] Auto-save error: {e}\nshell >>> ", end='', flush=True)

        
        thread = threading.Thread(target=save_worker, daemon=True)
        thread.start()
        return thread


class SessionRecovery:
    """Recover and restore sessions after server restart."""
    
    @staticmethod
    def restore_session(client_guid, session_data, ClientInfo):
        """
        Restore a single session.
        
        Args:
            client_guid: Client GUID
            session_data: Saved session metadata
            ClientInfo: ClientInfo class reference
            
        Returns:
            Restored ClientInfo object
        """
        session = ClientInfo()
        session.hostname = session_data.get('hostname', 'unknown')
        
        # Restore heartbeat (adjust for time passed)
        last_seen = session_data.get('last_seen', 0)
        session.heartbeat = time.time() - last_seen
        
        return session
    
    @staticmethod
    def cleanup_stale_sessions(sessions_data, max_age=3600):
        """
        Remove sessions that are too old.
        
        Args:
            sessions_data: Dict of session data
            max_age: Max age in seconds before session is considered stale
            
        Returns:
            Cleaned sessions_data dict
        """
        cleaned = {}
        for guid, data in sessions_data.items():
            last_seen = data.get('last_seen', 0)
            if last_seen < max_age:
                cleaned[guid] = data
            else:
                print(f"[*] Removing stale session: {guid[:16]}...")
        
        return cleaned
