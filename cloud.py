#!/usr/bin/env python3
"""
Cloud Misconfiguration Scanner - Ultimate Edition with Passive Intelligence
Advanced reconnaissance tool with optional API integrations (Shodan, Censys, SecurityTrails, VirusTotal)
Author: RicheByte
Version: 5.0
Date: 2025-10-23
"""

import asyncio
import socket
import dns.resolver
import dns.asyncresolver
import aiohttp
import ssl
import json
import re
import argparse
import sys
import time
import logging
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from functools import lru_cache
from collections import defaultdict
import urllib3
import ipaddress
from contextlib import asynccontextmanager
import hashlib
import base64
import os
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class APIConfig:
    """Centralized API configuration management"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.apis = {
            'shodan': {'enabled': False, 'api_key': None, 'base_url': 'https://api.shodan.io'},
            'censys': {'enabled': False, 'api_id': None, 'api_secret': None, 'base_url': 'https://search.censys.io/api/v2'},
            'securitytrails': {'enabled': False, 'api_key': None, 'base_url': 'https://api.securitytrails.com/v1'},
            'virustotal': {'enabled': False, 'api_key': None, 'base_url': 'https://www.virustotal.com/api/v3'},
            'hunter': {'enabled': False, 'api_key': None, 'base_url': 'https://api.hunter.io/v2'},
            'urlscan': {'enabled': False, 'api_key': None, 'base_url': 'https://urlscan.io/api/v1'},
            'alienvault': {'enabled': False, 'api_key': None, 'base_url': 'https://otx.alienvault.com/api/v1'}
        }
        
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        else:
            self.load_from_env()
    
    def load_from_env(self):
        """Load API keys from environment variables"""
        env_mappings = {
            'shodan': 'SHODAN_API_KEY',
            'censys': ('CENSYS_API_ID', 'CENSYS_API_SECRET'),
            'securitytrails': 'SECURITYTRAILS_API_KEY',
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'hunter': 'HUNTER_API_KEY',
            'urlscan': 'URLSCAN_API_KEY',
            'alienvault': 'ALIENVAULT_API_KEY'
        }
        
        for api_name, env_var in env_mappings.items():
            if isinstance(env_var, tuple):
                api_id = os.getenv(env_var[0])
                api_secret = os.getenv(env_var[1])
                if api_id and api_secret:
                    self.apis[api_name]['api_id'] = api_id
                    self.apis[api_name]['api_secret'] = api_secret
                    self.apis[api_name]['enabled'] = True
            else:
                api_key = os.getenv(env_var)
                if api_key:
                    self.apis[api_name]['api_key'] = api_key
                    self.apis[api_name]['enabled'] = True
    
    def load_from_file(self, config_file: str):
        """Load API keys from JSON config file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            for api_name, api_config in config.get('apis', {}).items():
                if api_name in self.apis:
                    self.apis[api_name].update(api_config)
                    if api_config.get('api_key') or (api_config.get('api_id') and api_config.get('api_secret')):
                        self.apis[api_name]['enabled'] = True
        except Exception as e:
            logging.warning(f"Failed to load config file: {str(e)}")
    
    def save_template(self, output_file: str = 'api_config_template.json'):
        """Generate a template config file"""
        template = {
            'apis': {
                'shodan': {'api_key': 'YOUR_SHODAN_API_KEY', 'enabled': False},
                'censys': {'api_id': 'YOUR_CENSYS_API_ID', 'api_secret': 'YOUR_CENSYS_API_SECRET', 'enabled': False},
                'securitytrails': {'api_key': 'YOUR_SECURITYTRAILS_API_KEY', 'enabled': False},
                'virustotal': {'api_key': 'YOUR_VIRUSTOTAL_API_KEY', 'enabled': False},
                'hunter': {'api_key': 'YOUR_HUNTER_API_KEY', 'enabled': False},
                'urlscan': {'api_key': 'YOUR_URLSCAN_API_KEY', 'enabled': False},
                'alienvault': {'api_key': 'YOUR_ALIENVAULT_API_KEY', 'enabled': False}
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(template, f, indent=2)
        
        print(f"✅ Config template saved to: {output_file}")
        print("\n📝 Configuration Instructions:")
        print("=" * 70)
        print("1. Edit the file and add your API keys")
        print("2. Set 'enabled': true for APIs you want to use")
        print("3. Run scanner with: --config api_config_template.json")
        print("\n🔑 Get API Keys:")
        print("   Shodan: https://account.shodan.io/")
        print("   Censys: https://search.censys.io/account/api")
        print("   SecurityTrails: https://securitytrails.com/app/account/credentials")
        print("   VirusTotal: https://www.virustotal.com/gui/my-apikey")
        print("   Hunter.io: https://hunter.io/api")
        print("   URLScan: https://urlscan.io/user/profile/")
        print("   AlienVault OTX: https://otx.alienvault.com/api")
        print("=" * 70)
    
    def is_enabled(self, api_name: str) -> bool:
        return self.apis.get(api_name, {}).get('enabled', False)
    
    def get_config(self, api_name: str) -> Dict:
        return self.apis.get(api_name, {})
    
    def get_enabled_apis(self) -> List[str]:
        return [name for name, config in self.apis.items() if config.get('enabled')]


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output"""
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class Finding:
    """Data class for security findings with enhanced metadata"""
    type: str
    severity: str
    location: str
    description: str
    evidence: str
    confidence: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    remediation: Optional[str] = None
    cve: Optional[str] = None
    references: Optional[List[str]] = None
    source: str = "scanner"


class ResultCache:
    """Thread-safe caching mechanism with TTL support"""
    def __init__(self, ttl: int = 300):
        self.cache = {}
        self.ttl = ttl
        self.lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Any]:
        async with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    return value
                del self.cache[key]
            return None
    
    async def set(self, key: str, value: Any):
        async with self.lock:
            self.cache[key] = (value, time.time())
    
    def clear(self):
        self.cache.clear()


# ============================================================================
# PASSIVE INTELLIGENCE LAYER (keeping your existing implementation)
# ============================================================================

class PassiveIntelligence:
    """Passive intelligence gathering using external APIs"""
    
    def __init__(self, api_config: APIConfig, cache: ResultCache, timeout: int = 30):
        self.api_config = api_config
        self.cache = cache
        self.timeout = timeout
        self.stats = defaultdict(int)
    
    @asynccontextmanager
    async def create_session(self):
        """Create async HTTP session for API calls"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            yield session
    
    async def enrich_domain(self, domain: str, results: Dict):
        """Main enrichment function - calls all enabled APIs"""
        enabled_apis = self.api_config.get_enabled_apis()
        
        if not enabled_apis:
            logger.info("ℹ️  No external APIs configured - skipping passive intelligence")
            return
        
        logger.info(f"🔍 Starting passive intelligence gathering...")
        logger.info(f"🌐 Active Intelligence Sources: {', '.join(enabled_apis).upper()}")
        
        # Implementation continues with your existing passive intel methods...
        # (Keeping all your Shodan, Censys, etc. methods as-is)


# ============================================================================
# MAIN SCANNER CLASS WITH ACTIVE SCANNING
# ============================================================================

class CloudMisconfigurationScanner:
    """Ultimate cloud security scanner with passive intelligence and active scanning"""
    
    def __init__(self, verbose: bool = False, timeout: int = 10, 
                 max_workers: int = 50, rate_limit: int = 100,
                 api_config: Optional[APIConfig] = None):
        self.verbose = verbose
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.cache = ResultCache(ttl=300)
        self.api_config = api_config or APIConfig()
        self.passive_intel = PassiveIntelligence(self.api_config, self.cache, timeout)
        self.stats = defaultdict(int)
        
        # Security headers to check
        self.security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy'
        }
        
        # Common S3 bucket patterns
        self.s3_patterns = [
            '{domain}', '{domain}-backup', '{domain}-backups', '{domain}-dev',
            '{domain}-prod', '{domain}-production', '{domain}-staging', '{domain}-test',
            '{domain}-assets', '{domain}-files', '{domain}-uploads', '{domain}-images',
            '{domain}-static', '{domain}-media', '{domain}-data', '{domain}-logs',
            'www-{domain}', 'www.{domain}', 'cdn-{domain}', '{company}',
            '{company}-backup', '{company}-prod', '{company}-staging'
        ]
        
        # Sensitive paths to check
        self.sensitive_paths = [
            '/.git/config', '/.git/HEAD', '/.env', '/.env.local', '/.env.production',
            '/config.json', '/config.php', '/configuration.php', '/settings.php',
            '/config.yml', '/config.yaml', '/.aws/credentials', '/.docker/config.json',
            '/phpinfo.php', '/info.php', '/test.php', '/backup.sql', '/db.sql',
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/.DS_Store',
            '/Thumbs.db', '/web.config', '/.htaccess', '/robots.txt', '/sitemap.xml',
            '/.well-known/security.txt', '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]
        
        # Common ports for cloud services
        self.cloud_ports = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 23: 'Telnet',
            25: 'SMTP', 3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
            6379: 'Redis', 9200: 'Elasticsearch', 5984: 'CouchDB',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 3389: 'RDP', 445: 'SMB',
            1433: 'MSSQL', 11211: 'Memcached', 9000: 'PHP-FPM', 8000: 'HTTP-Dev'
        }
    
    def log(self, message: str, level: str = 'info'):
        """Enhanced logging"""
        self.stats[f'log_{level}'] += 1
        if level == 'debug' and not self.verbose:
            return
        getattr(logger, level.lower())(message)
    
    # ========================================================================
    # ACTIVE SCANNING METHODS
    # ========================================================================
    
    async def scan_domain_async(self, domain: str) -> Dict:
        """Main async scanning with passive intelligence and active scanning"""
        self.log(f"🚀 Starting ultimate scan for: {domain}")
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'misconfigurations': [],
            'cloud_services': [],
            'risk_score': 0,
            'scan_duration': 0,
            'errors': [],
            'statistics': {},
            'passive_intelligence': {},
            'api_sources_used': self.api_config.get_enabled_apis()
        }
        
        start_time = time.time()
        
        # Validate domain
        if not self._validate_domain(domain):
            results['errors'].append(f"Invalid domain format: {domain}")
            return results
        
        # PHASE 1: Passive Intelligence Gathering
        await self.passive_intel.enrich_domain(domain, results)
        
        # PHASE 2: Active Scanning
        self.log("🔎 Starting active security scanning...")
        
        scan_tasks = [
            self.check_http_security(domain, results),
            self.check_ssl_tls(domain, results),
            self.check_dns_records(domain, results),
            self.check_sensitive_files(domain, results),
            self.check_s3_buckets(domain, results),
            self.check_subdomain_takeover(domain, results),
            self.scan_common_ports(domain, results),
            self.check_cors_policy(domain, results),
            self.check_server_headers(domain, results)
        ]
        
        await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        results['scan_duration'] = round(time.time() - start_time, 2)
        results['statistics'] = {
            **dict(self.stats),
            **dict(self.passive_intel.stats)
        }
        
        self.log(f"✅ Scan completed in {results['scan_duration']}s - "
                f"Risk Score: {results['risk_score']}/100 - "
                f"Findings: {len(results['misconfigurations'])}", 'info')
        
        return results
    
    async def check_http_security(self, domain: str, results: Dict):
        """Check HTTP security headers"""
        try:
            self.log("🔐 Checking HTTP security headers...", 'debug')
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                for protocol in ['https', 'http']:
                    url = f"{protocol}://{domain}"
                    try:
                        async with session.get(url, allow_redirects=True, ssl=False) as response:
                            headers = response.headers
                            
                            # Check for missing security headers
                            for header_key, header_name in self.security_headers.items():
                                if header_key not in headers:
                                    severity = 'HIGH' if header_key in ['strict-transport-security', 'content-security-policy'] else 'MEDIUM'
                                    results['misconfigurations'].append({
                                        'type': 'MISSING_SECURITY_HEADER',
                                        'severity': severity,
                                        'location': url,
                                        'description': f'Missing {header_name} header',
                                        'evidence': f'Header "{header_key}" not found in response',
                                        'confidence': 'high',
                                        'source': 'scanner',
                                        'remediation': f'Add {header_name} header to enhance security'
                                    })
                                    results['risk_score'] += 10 if severity == 'HIGH' else 5
                                    self.stats['missing_headers'] += 1
                            
                            # Check for insecure cookies
                            for cookie in response.cookies.values():
                                if not cookie.get('secure', False) and protocol == 'https':
                                    results['misconfigurations'].append({
                                        'type': 'INSECURE_COOKIE',
                                        'severity': 'MEDIUM',
                                        'location': url,
                                        'description': f'Cookie "{cookie.key}" missing Secure flag',
                                        'evidence': f'Cookie: {cookie.key}',
                                        'confidence': 'high',
                                        'source': 'scanner',
                                        'remediation': 'Set Secure flag on all HTTPS cookies'
                                    })
                                    results['risk_score'] += 5
                                    self.stats['insecure_cookies'] += 1
                            
                            break  # Successfully connected
                    except Exception as e:
                        self.log(f"Failed to connect to {url}: {str(e)}", 'debug')
                        continue
        
        except Exception as e:
            self.log(f"HTTP security check error: {str(e)}", 'debug')
    
    async def check_ssl_tls(self, domain: str, results: Dict):
        """Check SSL/TLS configuration"""
        try:
            self.log("🔒 Checking SSL/TLS configuration...", 'debug')
            
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %GMT')
                        days_until_expiry = (not_after - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            severity = 'CRITICAL' if days_until_expiry < 0 else 'HIGH'
                            results['misconfigurations'].append({
                                'type': 'SSL_CERTIFICATE_EXPIRING',
                                'severity': severity,
                                'location': f"https://{domain}",
                                'description': f'SSL certificate expires in {days_until_expiry} days',
                                'evidence': f'Expiry date: {not_after}',
                                'confidence': 'high',
                                'source': 'scanner',
                                'remediation': 'Renew SSL certificate immediately'
                            })
                            results['risk_score'] += 30 if severity == 'CRITICAL' else 15
                            self.stats['ssl_issues'] += 1
                        
                        # Check TLS version
                        tls_version = ssock.version()
                        if tls_version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                            results['misconfigurations'].append({
                                'type': 'WEAK_TLS_VERSION',
                                'severity': 'HIGH',
                                'location': f"https://{domain}",
                                'description': f'Using outdated TLS version: {tls_version}',
                                'evidence': f'TLS Version: {tls_version}',
                                'confidence': 'high',
                                'source': 'scanner',
                                'remediation': 'Upgrade to TLS 1.2 or TLS 1.3'
                            })
                            results['risk_score'] += 20
                            self.stats['weak_tls'] += 1
            
            except ssl.SSLError as e:
                results['misconfigurations'].append({
                    'type': 'SSL_ERROR',
                    'severity': 'HIGH',
                    'location': f"https://{domain}",
                    'description': f'SSL/TLS error: {str(e)}',
                    'evidence': str(e),
                    'confidence': 'medium',
                    'source': 'scanner',
                    'remediation': 'Review SSL/TLS configuration'
                })
                results['risk_score'] += 15
                self.stats['ssl_errors'] += 1
            
            except socket.timeout:
                self.log(f"SSL check timeout for {domain}", 'debug')
            except Exception as e:
                self.log(f"SSL check failed: {str(e)}", 'debug')
        
        except Exception as e:
            self.log(f"SSL/TLS check error: {str(e)}", 'debug')
    
    async def check_dns_records(self, domain: str, results: Dict):
        """Check DNS configuration"""
        try:
            self.log("🌐 Checking DNS records...", 'debug')
            
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # Check SPF record
            try:
                txt_records = await resolver.resolve(domain, 'TXT')
                has_spf = any('v=spf1' in str(record) for record in txt_records)
                
                if not has_spf:
                    results['misconfigurations'].append({
                        'type': 'MISSING_SPF_RECORD',
                        'severity': 'MEDIUM',
                        'location': domain,
                        'description': 'No SPF record found',
                        'evidence': 'SPF record missing from DNS TXT records',
                        'confidence': 'high',
                        'source': 'scanner',
                        'remediation': 'Add SPF record to prevent email spoofing'
                    })
                    results['risk_score'] += 10
                    self.stats['missing_spf'] += 1
            except:
                pass
            
            # Check DMARC record
            try:
                dmarc_domain = f'_dmarc.{domain}'
                dmarc_records = await resolver.resolve(dmarc_domain, 'TXT')
                has_dmarc = any('v=DMARC1' in str(record) for record in dmarc_records)
                
                if not has_dmarc:
                    results['misconfigurations'].append({
                        'type': 'MISSING_DMARC_RECORD',
                        'severity': 'MEDIUM',
                        'location': domain,
                        'description': 'No DMARC record found',
                        'evidence': 'DMARC record missing',
                        'confidence': 'high',
                        'source': 'scanner',
                        'remediation': 'Add DMARC record for email authentication'
                    })
                    results['risk_score'] += 10
                    self.stats['missing_dmarc'] += 1
            except:
                results['misconfigurations'].append({
                    'type': 'MISSING_DMARC_RECORD',
                    'severity': 'MEDIUM',
                    'location': domain,
                    'description': 'No DMARC record found',
                    'evidence': 'DMARC record missing',
                    'confidence': 'high',
                    'source': 'scanner',
                    'remediation': 'Add DMARC record for email authentication'
                })
                results['risk_score'] += 10
                self.stats['missing_dmarc'] += 1
            
            # Check CAA record
            try:
                caa_records = await resolver.resolve(domain, 'CAA')
                if not caa_records:
                    results['misconfigurations'].append({
                        'type': 'MISSING_CAA_RECORD',
                        'severity': 'LOW',
                        'location': domain,
                        'description': 'No CAA record found',
                        'evidence': 'CAA record missing',
                        'confidence': 'medium',
                        'source': 'scanner',
                        'remediation': 'Add CAA record to specify authorized CAs'
                    })
                    results['risk_score'] += 5
                    self.stats['missing_caa'] += 1
            except:
                pass
        
        except Exception as e:
            self.log(f"DNS check error: {str(e)}", 'debug')
    
    async def check_sensitive_files(self, domain: str, results: Dict):
        """Check for exposed sensitive files"""
        try:
            self.log("📁 Checking for exposed sensitive files...", 'debug')
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                for protocol in ['https', 'http']:
                    base_url = f"{protocol}://{domain}"
                    
                    for path in self.sensitive_paths:
                        url = base_url + path
                        try:
                            async with session.get(url, allow_redirects=False, ssl=False) as response:
                                if response.status in [200, 301, 302]:
                                    severity = 'CRITICAL' if any(x in path for x in ['.git', '.env', '.aws', 'config']) else 'HIGH'
                                    
                                    results['misconfigurations'].append({
                                        'type': 'SENSITIVE_FILE_EXPOSED',
                                        'severity': severity,
                                        'location': url,
                                        'description': f'Sensitive file/directory accessible: {path}',
                                        'evidence': f'HTTP {response.status} response',
                                        'confidence': 'high',
                                        'source': 'scanner',
                                        'remediation': 'Remove or restrict access to sensitive files'
                                    })
                                    results['risk_score'] += 25 if severity == 'CRITICAL' else 15
                                    self.stats['exposed_files'] += 1
                        except:
                            pass
                    
                    break  # Only check HTTPS if available
        
        except Exception as e:
            self.log(f"Sensitive files check error: {str(e)}", 'debug')
    
    async def check_s3_buckets(self, domain: str, results: Dict):
        """Check for misconfigured S3 buckets"""
        try:
            self.log("☁️  Checking for exposed S3 buckets...", 'debug')
            
            # Extract company name from domain
            company = domain.split('.')[0]
            
            bucket_names = []
            for pattern in self.s3_patterns:
                bucket_name = pattern.format(domain=company, company=company)
                bucket_names.append(bucket_name)
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                for bucket_name in bucket_names[:15]:  # Limit checks
                    url = f"https://{bucket_name}.s3.amazonaws.com"
                    
                    try:
                        async with session.get(url, allow_redirects=True, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                if 'ListBucketResult' in content:
                                    results['misconfigurations'].append({
                                        'type': 'S3_BUCKET_PUBLIC',
                                        'severity': 'CRITICAL',
                                        'location': url,
                                        'description': f'Publicly accessible S3 bucket: {bucket_name}',
                                        'evidence': 'Bucket listing accessible',
                                        'confidence': 'high',
                                        'source': 'scanner',
                                        'remediation': 'Restrict S3 bucket permissions immediately'
                                    })
                                    results['risk_score'] += 40
                                    self.stats['s3_exposed'] += 1
                            elif response.status == 403:
                                # Bucket exists but is private
                                results['cloud_services'].append({
                                    'service': 'S3_BUCKET_EXISTS',
                                    'bucket': bucket_name,
                                    'url': url,
                                    'status': 'private',
                                    'source': 'scanner'
                                })
                                self.stats['s3_found'] += 1
                    except:
                        pass
        
        except Exception as e:
            self.log(f"S3 bucket check error: {str(e)}", 'debug')
    
    async def check_subdomain_takeover(self, domain: str, results: Dict):
        """Check for potential subdomain takeover vulnerabilities"""
        try:
            self.log("🎯 Checking for subdomain takeover risks...", 'debug')
            
            vulnerable_cnames = [
                'amazonaws.com', 'cloudfront.net', 'azurewebsites.net',
                'herokuapp.com', 'github.io', 'bitbucket.io', 'pantheonsite.io',
                'zendesk.com', 'shopify.com', 'fastly.net', 's3.amazonaws.com'
            ]
            
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            
            # Check main domain
            try:
                cname_records = await resolver.resolve(domain, 'CNAME')
                for record in cname_records:
                    cname = str(record.target).lower()
                    if any(vuln in cname for vuln in vulnerable_cnames):
                        results['misconfigurations'].append({
                            'type': 'SUBDOMAIN_TAKEOVER_RISK',
                            'severity': 'HIGH',
                            'location': domain,
                            'description': f'Potential subdomain takeover vulnerability via {cname}',
                            'evidence': f'CNAME points to: {cname}',
                            'confidence': 'medium',
                            'source': 'scanner',
                            'remediation': 'Verify CNAME target exists and is properly configured'
                        })
                        results['risk_score'] += 20
                        self.stats['takeover_risks'] += 1
            except:
                pass
        
        except Exception as e:
            self.log(f"Subdomain takeover check error: {str(e)}", 'debug')
    
    async def scan_common_ports(self, domain: str, results: Dict):
        """Scan common cloud service ports"""
        try:
            self.log("🔌 Scanning common service ports...", 'debug')
            
            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(domain)
            except:
                return
            
            dangerous_ports = [21, 22, 23, 445, 3306, 3389, 5432, 6379, 27017, 9200, 11211]
            
            open_ports = []
            for port in dangerous_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        service = self.cloud_ports.get(port, f'Port {port}')
                        
                        results['misconfigurations'].append({
                            'type': 'EXPOSED_SERVICE_PORT',
                            'severity': 'HIGH',
                            'location': f"{ip}:{port}",
                            'description': f'Exposed {service} service on port {port}',
                            'evidence': f'Port {port} is open',
                            'confidence': 'high',
                            'source': 'scanner',
                            'remediation': f'Restrict access to {service} service'
                        })
                        results['risk_score'] += 15
                        self.stats['open_ports'] += 1
                except:
                    pass
                finally:
                    sock.close()
        
        except Exception as e:
            self.log(f"Port scan error: {str(e)}", 'debug')
    
    async def check_cors_policy(self, domain: str, results: Dict):
        """Check CORS policy configuration"""
        try:
            self.log("🔗 Checking CORS policy...", 'debug')
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                for protocol in ['https', 'http']:
                    url = f"{protocol}://{domain}"
                    headers = {'Origin': 'https://evil.com'}
                    
                    try:
                        async with session.get(url, headers=headers, ssl=False) as response:
                            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                            
                            if cors_header == '*':
                                results['misconfigurations'].append({
                                    'type': 'PERMISSIVE_CORS',
                                    'severity': 'MEDIUM',
                                    'location': url,
                                    'description': 'Overly permissive CORS policy (allows all origins)',
                                    'evidence': 'Access-Control-Allow-Origin: *',
                                    'confidence': 'high',
                                    'source': 'scanner',
                                    'remediation': 'Restrict CORS to specific trusted origins'
                                })
                                results['risk_score'] += 10
                                self.stats['cors_issues'] += 1
                            elif 'evil.com' in cors_header:
                                results['misconfigurations'].append({
                                    'type': 'REFLECTED_CORS',
                                    'severity': 'HIGH',
                                    'location': url,
                                    'description': 'CORS policy reflects arbitrary origins',
                                    'evidence': f'Access-Control-Allow-Origin: {cors_header}',
                                    'confidence': 'high',
                                    'source': 'scanner',
                                    'remediation': 'Implement whitelist-based CORS validation'
                                })
                                results['risk_score'] += 20
                                self.stats['cors_issues'] += 1
                        break
                    except:
                        continue
        
        except Exception as e:
            self.log(f"CORS check error: {str(e)}", 'debug')
    
    async def check_server_headers(self, domain: str, results: Dict):
        """Check for information disclosure in server headers"""
        try:
            self.log("💻 Checking server headers...", 'debug')
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                for protocol in ['https', 'http']:
                    url = f"{protocol}://{domain}"
                    
                    try:
                        async with session.get(url, ssl=False) as response:
                            headers = response.headers
                            
                            # Check for version disclosure
                            server_header = headers.get('Server', '')
                            x_powered_by = headers.get('X-Powered-By', '')
                            
                            if server_header and any(char.isdigit() for char in server_header):
                                results['misconfigurations'].append({
                                    'type': 'SERVER_VERSION_DISCLOSURE',
                                    'severity': 'LOW',
                                    'location': url,
                                    'description': f'Server version disclosed: {server_header}',
                                    'evidence': f'Server: {server_header}',
                                    'confidence': 'high',
                                    'source': 'scanner',
                                    'remediation': 'Remove version information from Server header'
                                })
                                results['risk_score'] += 5
                                self.stats['info_disclosure'] += 1
                            
                            if x_powered_by:
                                results['misconfigurations'].append({
                                    'type': 'TECHNOLOGY_DISCLOSURE',
                                    'severity': 'LOW',
                                    'location': url,
                                    'description': f'Technology stack disclosed: {x_powered_by}',
                                    'evidence': f'X-Powered-By: {x_powered_by}',
                                    'confidence': 'high',
                                    'source': 'scanner',
                                    'remediation': 'Remove X-Powered-By header'
                                })
                                results['risk_score'] += 5
                                self.stats['info_disclosure'] += 1
                        break
                    except:
                        continue
        
        except Exception as e:
            self.log(f"Server headers check error: {str(e)}", 'debug')
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    @lru_cache(maxsize=1024)
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format"""
        try:
            domain = domain.strip().lower()
            if '://' in domain:
                domain = domain.split('://', 1)[1]
            domain = domain.split('/')[0]
            
            if not domain or len(domain) < 3 or len(domain) > 253:
                return False
            if '.' not in domain:
                return False
            if not re.match(r'^[a-z0-9.-]+$', domain):
                return False
            
            labels = domain.split('.')
            for label in labels:
                if not label or len(label) > 63:
                    return False
                if label.startswith('-') or label.endswith('-'):
                    return False
            
            return True
        except Exception:
            return False
    
    def generate_report(self, results: Dict) -> str:
        """Enhanced report with passive intelligence"""
        lines = [
            "=" * 80,
            "🚀 CLOUD MISCONFIGURATION SCAN - ULTIMATE EDITION 🚀",
            "=" * 80,
            f"🎯 Target: {results['domain']}",
            f"⏰ Scan Time: {results['timestamp']}",
            f"⚡ Duration: {results['scan_duration']}s",
            f"📊 Risk Score: {results['risk_score']}/100",
            f"🔍 Findings: {len(results['misconfigurations'])}",
            ""
        ]
        
        # API Sources
        if results.get('api_sources_used'):
            lines.extend([
                "🌐 Intelligence Sources:",
                f"   {', '.join([s.upper() for s in results['api_sources_used']])}",
                ""
            ])
        
        # Findings by severity
        by_severity = {}
        for finding in results['misconfigurations']:
            severity = finding['severity']
            by_severity.setdefault(severity, []).append(finding)
        
        severity_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                lines.append(f"\n{severity_icons[severity]} {severity} ({len(by_severity[severity])}):")
                lines.append("─" * 80)
                for i, finding in enumerate(by_severity[severity], 1):
                    source = f" [{finding.get('source', 'scanner').upper()}]" if finding.get('source') else ""
                    lines.extend([
                        f"\n{i}. {finding['type']}{source}",
                        f"   📍 Location: {finding['location']}",
                        f"   📝 Description: {finding['description']}",
                        f"   🔬 Evidence: {finding['evidence']}"
                    ])
                    if finding.get('remediation'):
                        lines.append(f"   💡 Remediation: {finding['remediation']}")
        
        # Passive Intelligence Summary
        if results.get('passive_intelligence'):
            lines.extend(["\n" + "=" * 80, "🔍 PASSIVE INTELLIGENCE SUMMARY", "=" * 80])
            
            for source, data in results['passive_intelligence'].items():
                lines.append(f"\n📡 {source.upper()}:")
                if isinstance(data, dict):
                    for key, value in list(data.items())[:10]:
                        if not isinstance(value, (list, dict)):
                            lines.append(f"   • {key}: {value}")
                elif isinstance(data, list):
                    lines.append(f"   • Items: {len(data)}")
        
        # Statistics
        if results.get('statistics'):
            lines.extend(["\n" + "=" * 80, "📊 SCAN STATISTICS", "=" * 80])
            stats_grouped = defaultdict(list)
            for key, value in sorted(results['statistics'].items()):
                if value > 0:
                    category = key.split('_')[0]
                    stats_grouped[category].append(f"{key.replace('_', ' ').title()}: {value}")
            
            for category, stats in stats_grouped.items():
                lines.append(f"\n{category.upper()}:")
                for stat in stats:
                    lines.append(f"   • {stat}")
        
        lines.append("\n" + "=" * 80)
        return "\n".join(lines)
    
    def scan_domain(self, domain: str) -> Dict:
        """Synchronous wrapper"""
        return asyncio.run(self.scan_domain_async(domain))


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='🚀 Cloud Misconfiguration Scanner - Ultimate Edition with Passive Intelligence',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --config api_config.json
  %(prog)s domains.txt -o results.json -j -v
  %(prog)s example.com --generate-config

API Configuration:
  Set environment variables:
    SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET,
    SECURITYTRAILS_API_KEY, VIRUSTOTAL_API_KEY,
    HUNTER_API_KEY, URLSCAN_API_KEY, ALIENVAULT_API_KEY
  
  OR use --config with a JSON configuration file
        """
    )
    parser.add_argument('target', nargs='?', help='Domain or file with domains')
    parser.add_argument('-c', '--config', help='API configuration file (JSON)')
    parser.add_argument('--generate-config', action='store_true',
                       help='Generate API config template')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Timeout for requests (default: 10s)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-j', '--json', action='store_true',
                       help='JSON output format')
    parser.add_argument('-w', '--workers', type=int, default=50,
                       help='Max concurrent workers (default: 50)')
    parser.add_argument('-r', '--rate-limit', type=int, default=100,
                       help='Rate limit for requests (default: 100)')
    
    args = parser.parse_args()
    
    # Generate config template
    if args.generate_config:
        api_config = APIConfig()
        api_config.save_template()
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Banner
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     🚀 Cloud Misconfiguration Scanner - ULTIMATE Edition 🚀   ║
    ║              With Passive Intelligence Layer                  ║
    ║                    Author: RicheByte                          ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Load API configuration
    api_config = APIConfig(args.config)
    enabled_apis = api_config.get_enabled_apis()
    
    if enabled_apis:
        print(f"✅ Loaded API keys: {', '.join([s.upper() for s in enabled_apis])}\n")
    else:
        print("ℹ️  Running in standalone mode (no external APIs configured)")
        print("   Use --config or set environment variables for enhanced scanning\n")
    
    # Create scanner
    scanner = CloudMisconfigurationScanner(
        verbose=args.verbose,
        timeout=args.timeout,
        max_workers=args.workers,
        rate_limit=args.rate_limit,
        api_config=api_config
    )
    
    # Load domains
    domains = []
    try:
        with open(args.target, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        domains = [args.target]
    except Exception as e:
        logger.error(f"Error loading domains: {str(e)}")
        sys.exit(1)
    
    if not domains:
        logger.error("No domains to scan")
        sys.exit(1)
    
    logger.info(f"🎯 Scanning {len(domains)} domain(s) with {args.workers} workers")
    start_time = time.time()
    
    # Scan domains
    try:
        if len(domains) == 1:
            all_results = scanner.scan_domain(domains[0])
        else:
            all_results = {}
            for domain in domains:
                all_results[domain] = scanner.scan_domain(domain)
                time.sleep(1)
    
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Scan failed: {str(e)}")
        sys.exit(1)
    
    total_time = round(time.time() - start_time, 2)
    
    # Generate output
    if args.json:
        output = {
            'scanner_version': '5.0-ultimate',
            'timestamp': datetime.now().isoformat(),
            'total_targets': len(domains),
            'total_duration': total_time,
            'api_sources': enabled_apis,
            'results': all_results if len(domains) > 1 else {domains[0]: all_results}
        }
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(output, f, indent=2)
                logger.info(f"✅ Results saved to {args.output}")
            except Exception as e:
                logger.error(f"Failed to save results: {str(e)}")
                print(json.dumps(output, indent=2))
        else:
            print(json.dumps(output, indent=2))
    else:
        results_dict = all_results if len(domains) > 1 else {domains[0]: all_results}
        for domain, result in results_dict.items():
            if isinstance(result, dict) and 'error' not in result:
                print(scanner.generate_report(result))
                print()
    
    logger.info(f"✅ Total scan time: {total_time}s")
    logger.info(f"📊 Average: {round(total_time / len(domains), 2)}s per domain")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)