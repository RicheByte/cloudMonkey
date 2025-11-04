#!/usr/bin/env python3
"""
Setup and initialization script for Cloud Security Scanner
Checks dependencies, creates directories, and validates configuration

Author: RicheByte
Version: 1.0
"""

import sys
import os
import subprocess
from pathlib import Path


def print_banner():
    """Print setup banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                  Cloud Security Scanner - Setup Script                       ║
║                         Version 7.0 Enterprise                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_python_version():
    """Check if Python version is compatible"""
    print("🔍 Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print(f"❌ Python 3.10+ required. You have {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")
    return True


def install_dependencies():
    """Install required Python packages"""
    print("\n📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def check_dependencies():
    """Check if all required modules are available"""
    print("\n🔍 Checking installed modules...")
    
    required = {
        'aiohttp': 'Core HTTP library',
        'dnspython': 'DNS resolution',
        'yaml': 'YAML parser (PyYAML)',
        'cryptography': 'SSL/TLS support'
    }
    
    optional = {
        'rich': 'Rich terminal output',
        'fastapi': 'API server (future)',
    }
    
    missing = []
    
    for module, description in required.items():
        try:
            __import__(module)
            print(f"  ✅ {module:15s} - {description}")
        except ImportError:
            print(f"  ❌ {module:15s} - {description} (MISSING)")
            missing.append(module)
    
    print("\nOptional modules:")
    for module, description in optional.items():
        try:
            __import__(module)
            print(f"  ✅ {module:15s} - {description}")
        except ImportError:
            print(f"  ⚠️  {module:15s} - {description} (optional)")
    
    return len(missing) == 0


def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directory structure...")
    
    directories = [
        'data',
        'reports',
        'rules'
    ]
    
    for directory in directories:
        path = Path(directory)
        if not path.exists():
            path.mkdir(parents=True)
            print(f"  ✅ Created: {directory}/")
        else:
            print(f"  ℹ️  Exists:  {directory}/")
    
    return True


def check_rules():
    """Check if rule files exist"""
    print("\n📋 Checking rules engine...")
    
    rules_dir = Path('rules')
    if not rules_dir.exists():
        print("  ⚠️  Rules directory not found")
        return False
    
    rule_files = list(rules_dir.glob('*.yaml')) + list(rules_dir.glob('*.yml'))
    
    if len(rule_files) == 0:
        print("  ⚠️  No rule files found in rules/")
        return False
    
    print(f"  ✅ Found {len(rule_files)} rule files:")
    for rule_file in rule_files[:5]:  # Show first 5
        print(f"     - {rule_file.name}")
    
    if len(rule_files) > 5:
        print(f"     ... and {len(rule_files) - 5} more")
    
    return True


def check_scanner_files():
    """Check if main scanner files exist"""
    print("\n🔍 Checking scanner files...")
    
    files = {
        'cloud-pro.py': 'Main scanner',
        'db_manager.py': 'Database manager',
        'rules_engine.py': 'Rules engine',
        'requirements.txt': 'Dependencies'
    }
    
    all_exist = True
    for file, description in files.items():
        path = Path(file)
        if path.exists():
            size = path.stat().st_size / 1024  # KB
            print(f"  ✅ {file:20s} - {description} ({size:.1f} KB)")
        else:
            print(f"  ❌ {file:20s} - {description} (MISSING)")
            all_exist = False
    
    return all_exist


def run_test_scan():
    """Run a simple test to verify scanner works"""
    print("\n🧪 Running test scan...")
    
    try:
        # Import scanner modules
        from db_manager import DatabaseManager
        from rules_engine import RulesEngine
        
        print("  ✅ Database module imported")
        print("  ✅ Rules engine module imported")
        
        # Test database
        db = DatabaseManager(':memory:')  # In-memory DB for testing
        stats = db.get_statistics()
        print(f"  ✅ Database connection works")
        db.close()
        
        # Test rules engine
        rules = RulesEngine()
        print(f"  ✅ Rules engine loaded {len(rules.rules)} rules")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Test failed: {str(e)}")
        return False


def print_next_steps():
    """Print usage instructions"""
    print("\n" + "="*80)
    print("🎉 Setup Complete!")
    print("="*80)
    print("\n📖 Quick Start:")
    print("   python cloud-pro.py example.com")
    print("\n📊 With HTML report:")
    print("   python cloud-pro.py example.com --format html --output report.html")
    print("\n🔍 Aggressive scan:")
    print("   python cloud-pro.py example.com --mode aggressive")
    print("\n📚 More help:")
    print("   python cloud-pro.py --help")
    print("   cat QUICKSTART.md")
    print("\n🐳 Docker:")
    print("   docker build -t cloudmonkey .")
    print("   docker run cloudmonkey example.com")
    print("\n" + "="*80)


def main():
    """Main setup function"""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check if scanner files exist
    if not check_scanner_files():
        print("\n❌ Some required files are missing. Please ensure you have all files.")
        sys.exit(1)
    
    # Ask to install dependencies
    print("\n" + "-"*80)
    response = input("Install/upgrade dependencies from requirements.txt? (y/n): ")
    if response.lower() in ['y', 'yes']:
        if not install_dependencies():
            print("\n⚠️  Dependency installation failed. You may need to install manually.")
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Some required dependencies are missing.")
        print("💡 Install with: pip install -r requirements.txt")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Check rules
    check_rules()
    
    # Run test
    print("\n" + "-"*80)
    response = input("Run test scan to verify setup? (y/n): ")
    if response.lower() in ['y', 'yes']:
        if not run_test_scan():
            print("\n⚠️  Test scan failed. Check error messages above.")
        else:
            print("\n✅ All tests passed!")
    
    # Print next steps
    print_next_steps()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Setup error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
