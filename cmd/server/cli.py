# cli.py
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
            for client_guid, client_info in sessions_map.items():
                if client_guid.startswith(word):
                    hostname = client_info.get('hostname', 'unknown')
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
        if buffer:
            print(buffer)
        del console_buffer[session_id]
    
    current_session = session_id
    
    # Create session for interactive input
    session = PromptSession(history=InMemoryHistory())
    
    try:
        while True:
            # Read input from user
            try:
                line = session.prompt('')
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            
            # Check for background command
            if line.strip() == "background":
                return
            
            # Encode command and add to packet queue
            init_packet, data_packets = encode(
                (line + "\n").encode(),
                False,  # is_request=False for server
                encryption_key,
                target_domain,
                None  # client_guid not needed for server->client
            )
            
            # Initialize packet queue for this session if needed
            if session_id not in packet_queue:
                packet_queue[session_id] = []
            
            # Add packets to queue
            packet_queue[session_id].append(init_packet)
            for packet in data_packets:
                packet_queue[session_id].append(packet)
    
    except Exception as e:
        print(f"Error during interaction: {e}")


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
            print(f"Interacting with session {session_id}.")
            interact(session_id)
        else:
            print("Usage: sessions [id]")
            # Optionally list all sessions
            if sessions_map:
                print("\nActive sessions:")
                for guid, info in sessions_map.items():
                    hostname = info.get('hostname', 'unknown')
                    print(f"  {guid} - {hostname}")
    
    else:
        print(f"Unknown command: {cmd}")


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
