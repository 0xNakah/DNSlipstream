#!/usr/bin/env python3
# build_binaries.py - Build standalone binaries for DNSlipstream

import os
import sys
import subprocess
import shutil
from pathlib import Path


def print_header(msg):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}\n")


def build_client(domain_name, encryption_key):
    """Build client binary."""
    print_header("Building Client Binary")
    
    # Create build command
    cmd = [
        'pyinstaller',
        '--onefile',                    # Single executable
        '--name', 'dnslipstream',       # Output name (like 'chashell')
        '--clean',
        '--noconfirm',
        '--add-data', 'lib:lib',        # Include lib directory
        f'--add-data=lib/protocol/comm_pb2.py:lib/protocol',
        '--hidden-import', 'lib.protocol.comm_pb2',
        '--hidden-import', 'lib.transport.stream',
        '--hidden-import', 'lib.crypto.symetric',
        '--hidden-import', 'lib.logging',
        '--console',
        'cmd/shell/shell.py'
    ]
    
    # On Windows, use semicolon for --add-data
    if sys.platform == 'win32':
        cmd = [arg.replace(':', ';') if '--add-data' in arg else arg for arg in cmd]
    
    subprocess.run(cmd, check=True)
    
    print(f"✓ Client binary created: dist/dnslipstream")


def build_server(domain_name, encryption_key):
    """Build server binary."""
    print_header("Building Server Binary")
    
    cmd = [
        'pyinstaller',
        '--onefile',
        '--name', 'dnslipstream-server',  # Like 'chaserv'
        '--clean',
        '--noconfirm',
        '--add-data', 'lib:lib',
        '--add-data', 'cmd/server/cli.py:cmd/server',
        '--hidden-import', 'lib.protocol.comm_pb2',
        '--hidden-import', 'lib.crypto.symetric',
        '--hidden-import', 'dnslib',
        '--hidden-import', 'prompt_toolkit',
        '--console',
        'cmd/server/serv.py'
    ]
    
    if sys.platform == 'win32':
        cmd = [arg.replace(':', ';') if '--add-data' in arg else arg for arg in cmd]
    
    subprocess.run(cmd, check=True)
    
    print(f"✓ Server binary created: dist/dnslipstream-server")


def build_all(domain_name, encryption_key, osarch=None):
    """Build both client and server."""
    print_header("DNSlipstream Binary Builder")
    
    # Check protocol buffer exists
    if not Path('lib/protocol/comm_pb2.py').exists():
        print("✗ Protocol buffer not compiled!")
        print("Run: protoc --python_out=lib/protocol proto/comm.proto")
        sys.exit(1)
    
    try:
        build_client(domain_name, encryption_key)
        build_server(domain_name, encryption_key)
        
        print_header("Build Complete!")
        
        # Show output files
        print("Binaries created:")
        print(f"  Client: dist/dnslipstream")
        print(f"  Server: dist/dnslipstream-server")
        print()
        
        print("Usage:")
        print(f"\n  Server:")
        print(f"    export ENCRYPTION_KEY={encryption_key}")
        print(f"    export DOMAIN_NAME={domain_name}")
        print(f"    sudo -E ./dist/dnslipstream-server")
        
        print(f"\n  Client:")
        print(f"    export ENCRYPTION_KEY={encryption_key}")
        print(f"    export DOMAIN_NAME={domain_name}")
        print(f"    ./dist/dnslipstream")
        print()
        
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Build failed: {e}")
        sys.exit(1)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Build DNSlipstream binaries')
    parser.add_argument('--domain', default='c.example.com', 
                       help='Target domain name')
    parser.add_argument('--key', 
                       help='Encryption key (auto-generated if not provided)')
    parser.add_argument('--osarch', 
                       help='Target OS/Arch (e.g., linux/amd64, windows/386)')
    parser.add_argument('target', 
                       choices=['all', 'client', 'server'],
                       help='What to build')
    
    args = parser.parse_args()
    
    # Generate key if not provided
    if not args.key:
        import os
        args.key = os.urandom(32).hex()
        print(f"Generated encryption key: {args.key}")
    
    try:
        if args.target == 'all':
            build_all(args.domain, args.key, args.osarch)
        elif args.target == 'client':
            build_client(args.domain, args.key)
        elif args.target == 'server':
            build_server(args.domain, args.key)
    except KeyboardInterrupt:
        print("\n\nBuild cancelled")
        sys.exit(1)


if __name__ == "__main__":
    main()
