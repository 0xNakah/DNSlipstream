# Makefile or build script
"""
Setup script for DNSlipstream
"""

import subprocess
import sys
import os

def check_protoc():
    """Check if protoc is installed."""
    try:
        result = subprocess.run(['protoc', '--version'], 
                              capture_output=True, text=True)
        print(f"✓ Found {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        return False

def install_deps():
    """Install Python dependencies."""
    print("Installing Python dependencies...")
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])

def compile_proto():
    """Compile protocol buffers."""
    if not check_protoc():
        print("\n✗ protoc not found!")
        print("\nInstall protoc:")
        print("  Windows: choco install protoc")
        print("  macOS:   brew install protobuf")
        print("  Linux:   sudo apt install protobuf-compiler")
        sys.exit(1)
    
    print("Compiling protocol buffers...")
    subprocess.run(['protoc', '--python_out=lib/protocol', 'proto/comm.proto'], check=True)
    print("✓ Protocol buffers compiled")

def main():
    print("=== DNSlipstream Setup ===\n")
    install_deps()
    compile_proto()
    print("\n✓ Setup complete! You can now run:")
    print("  python cmd/server/serv.py")
    print("  python cmd/shell/shell.py")

if __name__ == "__main__":
    main()
