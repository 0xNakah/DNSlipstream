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
    
    # Base command
    cmd = [
        'pyinstaller',
        '--onefile',
        '--name', 'dnslipstream',
        '--clean',
        '--noconfirm',
        '--console',
        
        # Hidden imports for PyNaCl and dependencies
        '--hidden-import', '_cffi_backend',
        '--hidden-import', 'nacl',
        '--hidden-import', 'nacl.secret',
        '--hidden-import', 'nacl.bindings',
        '--hidden-import', 'nacl.encoding',
        '--hidden-import', 'nacl.utils',
        
        # Hidden imports for your modules
        '--hidden-import', 'lib.protocol.comm_pb2',
        '--hidden-import', 'lib.transport.stream',
        '--hidden-import', 'lib.transport.encoding',
        '--hidden-import', 'lib.transport.dns',
        '--hidden-import', 'lib.transport.polling',
        '--hidden-import', 'lib.crypto.symetric',
        '--hidden-import', 'lib.spliting.split',
        '--hidden-import', 'lib.logging',
        
        # Hidden imports for other dependencies
        '--hidden-import', 'dns',
        '--hidden-import', 'dns.resolver',
        '--hidden-import', 'dns.message',
        '--hidden-import', 'dns.query',
        
        # Collect all submodules
        '--collect-all', 'nacl',
        '--collect-all', 'cffi',
        '--collect-all', '_cffi_backend',
        
        'cmd/shell/shell.py'
    ]
    
    subprocess.run(cmd, check=True)
    print(f"✓ Client binary created: dist/dnslipstream")


def build_server(domain_name, encryption_key):
    """Build server binary."""
    print_header("Building Server Binary")
    
    cmd = [
        'pyinstaller',
        '--onefile',
        '--name', 'dnslipstream-server',
        '--clean',
        '--noconfirm',
        '--console',
        
        # Hidden imports for PyNaCl
        '--hidden-import', '_cffi_backend',
        '--hidden-import', 'nacl',
        '--hidden-import', 'nacl.secret',
        '--hidden-import', 'nacl.bindings',
        
        # Hidden imports for your modules
        '--hidden-import', 'lib.protocol.comm_pb2',
        '--hidden-import', 'lib.crypto.symetric',
        '--hidden-import', 'lib.logging',
        '--hidden-import', 'cmd.server.cli',
        
        # Hidden imports for dnslib
        '--hidden-import', 'dnslib',
        '--hidden-import', 'dnslib.server',
        
        # Hidden imports for prompt_toolkit
        '--hidden-import', 'prompt_toolkit',
        '--hidden-import', 'prompt_toolkit.completion',
        
        # Collect all submodules
        '--collect-all', 'nacl',
        '--collect-all', 'cffi',
        '--collect-all', 'dnslib',
        '--collect-all', 'prompt_toolkit',
        
        'cmd/server/serv.py'
    ]
    
    subprocess.run(cmd, check=True)
    print(f"✓ Server binary created: dist/dnslipstream-server")


def build_all(domain_name, encryption_key):
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
        
        print("Binaries created:")
        print(f"  Client: dist/dnslipstream.exe")
        print(f"  Server: dist/dnslipstream-server.exe")
        print()
        
        print("Usage:")
        print(f"\n  Server:")
        print(f"    set ENCRYPTION_KEY={encryption_key}")
        print(f"    set DOMAIN_NAME={domain_name}")
        print(f"    .\\dist\\dnslipstream-server.exe")
        
        print(f"\n  Client:")
        print(f"    set ENCRYPTION_KEY={encryption_key}")
        print(f"    set DOMAIN_NAME={domain_name}")
        print(f"    .\\dist\\dnslipstream.exe")
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
            build_all(args.domain, args.key)
        elif args.target == 'client':
            build_client(args.domain, args.key)
        elif args.target == 'server':
            build_server(args.domain, args.key)
    except KeyboardInterrupt:
        print("\n\nBuild cancelled")
        sys.exit(1)


if __name__ == "__main__":
    main()
