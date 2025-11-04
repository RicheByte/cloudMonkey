#!/usr/bin/env python3
"""
Rules Engine for Cloud Security Scanner
Signature-based detection using YAML rule definitions

Author: RicheByte
Version: 1.0
"""

import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class SecurityRule:
    """Represents a security detection rule"""
    id: str
    name: str
    description: str
    severity: str
    confidence: str
    category: str
    tags: List[str] = field(default_factory=list)
    patterns: List[Dict] = field(default_factory=list)
    response_codes: List[int] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss: Dict = field(default_factory=dict)
    owasp_top10: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    compliance: Dict = field(default_factory=dict)
    
    @classmethod
    def from_yaml(cls, rule_dict: Dict) -> 'SecurityRule':
        """Create SecurityRule from YAML dictionary"""
        return cls(
            id=rule_dict.get('id', 'UNKNOWN'),
            name=rule_dict.get('name', 'Unknown Rule'),
            description=rule_dict.get('description', ''),
            severity=rule_dict.get('severity', 'info').upper(),
            confidence=rule_dict.get('confidence', 'medium'),
            category=rule_dict.get('category', 'general'),
            tags=rule_dict.get('tags', []),
            patterns=rule_dict.get('patterns', []),
            response_codes=rule_dict.get('response_codes', []),
            remediation=rule_dict.get('remediation', ''),
            references=rule_dict.get('references', []),
            cvss=rule_dict.get('cvss', {}),
            owasp_top10=rule_dict.get('owasp_top10', []),
            mitre_attack=rule_dict.get('mitre_attack', []),
            compliance=rule_dict.get('compliance', {})
        )


class RulesEngine:
    """Load and match YAML-based security rules"""
    
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: List[SecurityRule] = []
        self.rules_by_id: Dict[str, SecurityRule] = {}
        self.rules_by_category: Dict[str, List[SecurityRule]] = {}
        self.load_rules()
    
    def load_rules(self):
        """Load all YAML rules from rules directory"""
        if not self.rules_dir.exists():
            print(f"⚠️  Rules directory not found: {self.rules_dir}")
            return
        
        rule_files = list(self.rules_dir.glob("*.yaml")) + list(self.rules_dir.glob("*.yml"))
        
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_data = yaml.safe_load(f)
                    
                    if not rule_data:
                        continue
                    
                    rule = SecurityRule.from_yaml(rule_data)
                    self.rules.append(rule)
                    self.rules_by_id[rule.id] = rule
                    
                    # Index by category
                    if rule.category not in self.rules_by_category:
                        self.rules_by_category[rule.category] = []
                    self.rules_by_category[rule.category].append(rule)
                    
            except Exception as e:
                print(f"⚠️  Failed to load rule {rule_file}: {str(e)}")
        
        print(f"✅ Loaded {len(self.rules)} security rules from {len(rule_files)} files")
    
    def match_response(self, url: str, response_body: str, response_code: int, 
                      headers: Dict[str, str] = None) -> List[SecurityRule]:
        """Match response against all rules and return matching rules"""
        matched_rules = []
        headers = headers or {}
        
        for rule in self.rules:
            if self._rule_matches(rule, url, response_body, response_code, headers):
                matched_rules.append(rule)
        
        return matched_rules
    
    def match_by_category(self, category: str, url: str, response_body: str, 
                         response_code: int, headers: Dict[str, str] = None) -> List[SecurityRule]:
        """Match response against rules in specific category"""
        matched_rules = []
        headers = headers or {}
        
        category_rules = self.rules_by_category.get(category, [])
        for rule in category_rules:
            if self._rule_matches(rule, url, response_body, response_code, headers):
                matched_rules.append(rule)
        
        return matched_rules
    
    def _rule_matches(self, rule: SecurityRule, url: str, response_body: str, 
                     response_code: int, headers: Dict[str, str]) -> bool:
        """Check if a rule matches the given response"""
        # Check response code if specified
        if rule.response_codes and response_code not in rule.response_codes:
            return False
        
        # Check all patterns
        for pattern in rule.patterns:
            pattern_type = pattern.get('type', 'response_body')
            
            if pattern_type == 'response_body':
                if not self._match_body_pattern(pattern, response_body):
                    return False
            
            elif pattern_type == 'url':
                if not self._match_url_pattern(pattern, url):
                    return False
            
            elif pattern_type == 'header_missing':
                if not self._match_missing_headers(pattern, headers):
                    return False
            
            elif pattern_type == 'header_value':
                if not self._match_header_value(pattern, headers):
                    return False
        
        return True if rule.patterns else False
    
    def _match_body_pattern(self, pattern: Dict, response_body: str) -> bool:
        """Match pattern against response body"""
        if 'regex' in pattern:
            return bool(re.search(pattern['regex'], response_body, re.IGNORECASE))
        
        if 'contains' in pattern:
            return pattern['contains'].lower() in response_body.lower()
        
        if 'equals' in pattern:
            return response_body.strip() == pattern['equals']
        
        return False
    
    def _match_url_pattern(self, pattern: Dict, url: str) -> bool:
        """Match pattern against URL"""
        if 'contains' in pattern:
            return pattern['contains'].lower() in url.lower()
        
        if 'paths' in pattern:
            return any(path.lower() in url.lower() for path in pattern['paths'])
        
        if 'regex' in pattern:
            return bool(re.search(pattern['regex'], url, re.IGNORECASE))
        
        return False
    
    def _match_missing_headers(self, pattern: Dict, headers: Dict[str, str]) -> bool:
        """Check if specified headers are missing"""
        required_headers = pattern.get('headers', [])
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # At least one header must be missing
        missing_count = sum(1 for h in required_headers if h.lower() not in headers_lower)
        return missing_count > 0
    
    def _match_header_value(self, pattern: Dict, headers: Dict[str, str]) -> bool:
        """Match header value against pattern"""
        header_name = pattern.get('header', '').lower()
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        if header_name not in headers_lower:
            return False
        
        header_value = headers_lower[header_name]
        
        if 'contains' in pattern:
            return pattern['contains'].lower() in header_value.lower()
        
        if 'regex' in pattern:
            return bool(re.search(pattern['regex'], header_value, re.IGNORECASE))
        
        if 'equals' in pattern:
            return header_value.lower() == pattern['equals'].lower()
        
        return False
    
    def get_rule_by_id(self, rule_id: str) -> Optional[SecurityRule]:
        """Get specific rule by ID"""
        return self.rules_by_id.get(rule_id)
    
    def get_rules_by_severity(self, severity: str) -> List[SecurityRule]:
        """Get all rules of specific severity"""
        return [r for r in self.rules if r.severity.upper() == severity.upper()]
    
    def get_rules_by_tag(self, tag: str) -> List[SecurityRule]:
        """Get all rules with specific tag"""
        return [r for r in self.rules if tag.lower() in [t.lower() for t in r.tags]]
    
    def get_compliance_mapping(self, framework: str) -> Dict[str, List[str]]:
        """Get compliance mapping for a framework (ISO27001, SOC2, NIST, PCI-DSS)"""
        mapping = {}
        
        for rule in self.rules:
            if framework.lower() in rule.compliance:
                controls = rule.compliance[framework.lower()]
                mapping[rule.id] = controls
        
        return mapping
    
    def enrich_finding(self, finding: Dict, rule_id: str) -> Dict:
        """Enrich a finding with rule metadata (CVSS, OWASP, MITRE, compliance)"""
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return finding
        
        # Add enhanced metadata
        if rule.cvss:
            finding['cvss'] = rule.cvss
        
        if rule.owasp_top10:
            finding['owasp_mapping'] = rule.owasp_top10
        
        if rule.mitre_attack:
            finding['mitre_attack'] = rule.mitre_attack
        
        if rule.compliance:
            finding['compliance'] = rule.compliance
        
        if rule.remediation:
            finding['remediation'] = rule.remediation
        
        if rule.references:
            finding['references'] = rule.references
        
        return finding
    
    def generate_compliance_report(self, findings: List[Dict], framework: str) -> Dict:
        """Generate compliance report for specific framework"""
        report = {
            'framework': framework,
            'total_findings': len(findings),
            'controls_affected': set(),
            'findings_by_control': {},
            'compliance_score': 100.0
        }
        
        for finding in findings:
            compliance_data = finding.get('compliance', {})
            if framework.lower() in compliance_data:
                controls = compliance_data[framework.lower()]
                for control in controls:
                    report['controls_affected'].add(control)
                    if control not in report['findings_by_control']:
                        report['findings_by_control'][control] = []
                    report['findings_by_control'][control].append(finding)
        
        report['controls_affected'] = sorted(list(report['controls_affected']))
        report['controls_affected_count'] = len(report['controls_affected'])
        
        # Simple compliance score (could be enhanced)
        if findings:
            severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            total_weight = sum(severity_weights.get(f.get('severity', 'INFO'), 0) for f in findings)
            report['compliance_score'] = max(0, 100 - total_weight)
        
        return report
    
    def get_statistics(self) -> Dict:
        """Get rules engine statistics"""
        stats = {
            'total_rules': len(self.rules),
            'by_severity': {},
            'by_category': {},
            'by_tag': {}
        }
        
        # Count by severity
        for rule in self.rules:
            severity = rule.severity.upper()
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        
        # Count by category
        for category, rules in self.rules_by_category.items():
            stats['by_category'][category] = len(rules)
        
        # Count by tag
        for rule in self.rules:
            for tag in rule.tags:
                stats['by_tag'][tag] = stats['by_tag'].get(tag, 0) + 1
        
        return stats
