import re
from typing import Dict, List, Optional, Union
import json
from pathlib import Path
from urllib.parse import urlparse
from ipaddress import ip_network, ip_address
import base64
from rule_engine.parser import RuleParser
import logging

logger = logging.getLogger(__name__)

class SuricataRuleConverter:
    """Convert Suricata rules to native WAF rule format"""

    # Suricata action to WAF action mapping
    ACTION_MAP = {
        "alert": "log",
        "drop": "block",
        "reject": "block",
        "pass": "allow"
    }

    # Protocol mapping
    PROTOCOL_MAP = {
        "http": "http",
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp"
    }

    def __init__(self, parser: Optional[RuleParser] = None):
        self.parser = parser or RuleParser()
        self._current_rule_id = 0
        self._sid_map = {}  # Track seen SIDs to avoid duplicates

    def convert_rule(self, suricata_rule: str) -> Dict:
        """Convert a single Suricata rule to native format"""
        try:
            # Parse basic rule components
            parts = self._parse_rule_header(suricata_rule)
            if not parts:
                raise ValueError("Invalid Suricata rule format")

            # Extract rule options
            options = self._parse_rule_options(parts["options"])
            if not options:
                raise ValueError("No valid options found in rule")

            # Build the base rule
            rule = {
                "id": f"suricata_{parts.get('sid', self._generate_rule_id())}",
                "description": options.get("msg", "Suricata converted rule"),
                "action": self.ACTION_MAP.get(parts["action"], "block"),
                "severity": self._map_severity(options.get("classtype", "unknown")),
                "tags": self._get_tags(options),
                "source": "suricata",
                "original_rule": suricata_rule.strip(),
                "condition": self._build_condition(parts, options)
            }

            # Validate the converted rule
            if self.parser and not self.parser.validate_rule(rule):
                logger.warning(f"Converted rule failed validation: {rule['id']}")
                return None

            return rule

        except Exception as e:
            logger.error(f"Error converting rule: {str(e)}")
            return None

    def convert_rule_file(self, file_path: Union[str, Path]) -> List[Dict]:
        """Convert a Suricata rule file to native format"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {file_path}")

        rules = []
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                rule = self.convert_rule(line)
                if rule:
                    # Avoid duplicate SIDs
                    if rule['id'] not in self._sid_map:
                        rules.append(rule)
                        self._sid_map[rule['id']] = True

        return rules

    def _parse_rule_header(self, rule: str) -> Optional[Dict]:
        """Parse the header portion of a Suricata rule"""
        header_pattern = re.compile(
            r'^(?P<action>\w+)\s+'  # Action
            r'(?P<protocol>\w+)\s+'  # Protocol
            r'(?P<src_ip>[^\s]+)\s+'  # Source IP
            r'(?P<src_port>[^\s]+)\s+'  # Source port
            r'(?P<direction>[^\s]+)\s+'  # Direction
            r'(?P<dst_ip>[^\s]+)\s+'  # Destination IP
            r'(?P<dst_port>[^\s]+)\s+'  # Destination port
            r'\((?P<options>.*)\)\s*$'  # Options
        )
        match = header_pattern.match(rule)
        if not match:
            return None

        parts = match.groupdict()
        parts["protocol"] = parts["protocol"].lower()
        return parts

    def _parse_rule_options(self, options: str) -> Dict:
        """Parse the options portion of a Suricata rule"""
        option_pattern = re.compile(
            r'(?P<key>[^:;]+):\s*"(?P<value>(?:\\.|[^"\\])*?)"|'  # key:"value"
            r'(?P<flag>[^;]+);'  # flag;
        )

        parsed = {}
        for match in option_pattern.finditer(options):
            if match.group('key') and match.group('value'):
                key = match.group('key').strip()
                value = match.group('value')
                parsed[key] = value
            elif match.group('flag'):
                flag = match.group('flag').strip()
                parsed[flag] = True

        return parsed

    def _build_condition(self, parts: Dict, options: Dict) -> Dict:
        """Build a condition tree from Suricata rule parts"""
        conditions = []

        # Protocol condition
        if parts["protocol"] in self.PROTOCOL_MAP:
            conditions.append({
                "field": "protocol",
                "operator": "equals",
                "value": self.PROTOCOL_MAP[parts["protocol"]]
            })

        # IP address conditions
        src_ip_cond = self._build_ip_condition("source.ip", parts["src_ip"])
        if src_ip_cond:
            conditions.append(src_ip_cond)

        dst_ip_cond = self._build_ip_condition("destination.ip", parts["dst_ip"])
        if dst_ip_cond:
            conditions.append(dst_ip_cond)

        # Port conditions
        src_port_cond = self._build_port_condition("source.port", parts["src_port"])
        if src_port_cond:
            conditions.append(src_port_cond)

        dst_port_cond = self._build_port_condition("destination.port", parts["dst_port"])
        if dst_port_cond:
            conditions.append(dst_port_cond)

        # Content matches
        content_conditions = self._build_content_conditions(options)
        if content_conditions:
            conditions.extend(content_conditions)

        # HTTP specific conditions
        http_conditions = self._build_http_conditions(options)
        if http_conditions:
            conditions.extend(http_conditions)

        # Handle single condition case
        if len(conditions) == 1:
            return conditions[0]

        # Default to AND for multiple conditions
        return {"and": conditions}

    def _build_ip_condition(self, field: str, ip_spec: str) -> Optional[Dict]:
        """Build an IP address condition"""
        if ip_spec == "any":
            return None

        if ip_spec.startswith('!') and '$' not in ip_spec:
            operator = "notIn"
            ip_spec = ip_spec[1:]
        elif '$' in ip_spec:
            # Skip variable references - we can't handle these
            return None
        else:
            operator = "in"

        ip_list = []
        for ip in ip_spec.split(','):
            ip = ip.strip()
            if '/' in ip:
                # CIDR range
                try:
                    ip_list.append(str(ip_network(ip, strict=False)))
                except ValueError:
                    continue
            elif ip != 'any':
                # Single IP
                try:
                    ip_list.append(str(ip_address(ip)))
                except ValueError:
                    continue

        if not ip_list:
            return None

        return {
            "field": field,
            "operator": operator,
            "value": ip_list
        }

    def _build_port_condition(self, field: str, port_spec: str) -> Optional[Dict]:
        """Build a port condition"""
        if port_spec == 'any':
            return None

        if port_spec.startswith('!'):
            operator = "notIn"
            port_spec = port_spec[1:]
        else:
            operator = "in"

        ports = []
        for part in port_spec.split(','):
            part = part.strip()
            if ':' in part:
                # Port range
                try:
                    start, end = map(int, part.split(':'))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    continue
            elif part != 'any':
                # Single port
                try:
                    ports.append(int(part))
                except ValueError:
                    continue

        if not ports:
            return None

        return {
            "field": field,
            "operator": operator,
            "value": ports
        }

    def _build_content_conditions(self, options: Dict) -> List[Dict]:
        """Build conditions for content matches"""
        conditions = []

        # Handle content matches
        if 'content' in options:
            content = options['content']
            nocase = options.get('nocase', False)
            modifier = 'matches' if nocase else 'regex'

            # Handle base64 encoded content
            if options.get('base64'):
                try:
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception:
                    pass

            conditions.append({
                "field": "request.raw",
                "operator": modifier,
                "value": re.escape(content)
            })

        # Handle PCRE matches
        if 'pcre' in options:
            pcre_pattern = options['pcre']
            # Remove the PCRE modifiers and delimiters
            if pcre_pattern.startswith('/') and pcre_pattern.endswith('/'):
                pcre_pattern = pcre_pattern[1:-1]
                # Remove modifiers
                pcre_pattern = re.sub(r'/[imxsADSUXJu]*$', '', pcre_pattern)

            conditions.append({
                "field": "request.raw",
                "operator": "regex",
                "value": pcre_pattern
            })

        return conditions

    def _build_http_conditions(self, options: Dict) -> List[Dict]:
        """Build HTTP-specific conditions"""
        conditions = []

        # HTTP method
        if 'http_method' in options:
            methods = options['http_method'].split('|')
            conditions.append({
                "field": "request.method",
                "operator": "in",
                "value": [m.upper() for m in methods]
            })

        # HTTP URI
        if 'http_uri' in options:
            uri_pattern = options['http_uri']
            conditions.append({
                "field": "request.uri",
                "operator": "regex",
                "value": self._convert_uricontent(uri_pattern)
            })

        # HTTP header
        if 'http_header' in options:
            header_pattern = options['http_header']
            conditions.append({
                "field": "request.headers",
                "operator": "contains",
                "value": header_pattern
            })

        # HTTP user agent
        if 'http_user_agent' in options:
            ua_pattern = options['http_user_agent']
            conditions.append({
                "field": "request.headers.user-agent",
                "operator": "regex",
                "value": self._convert_uricontent(ua_pattern)
            })

        # HTTP host
        if 'http_host' in options:
            host_pattern = options['http_host']
            conditions.append({
                "field": "request.headers.host",
                "operator": "regex",
                "value": self._convert_uricontent(host_pattern)
            })

        return conditions

    def _convert_uricontent(self, pattern: str) -> str:
        """Convert Suricata uricontent to regex"""
        # Simple conversion - in a real implementation you'd handle all uricontent features
        return re.escape(pattern).replace(r'\\*', '.*')

    def _map_severity(self, classtype: str) -> str:
        """Map Suricata classtype to severity"""
        classtype = classtype.lower()
        if 'exploit' in classtype or 'trojan' in classtype:
            return 'critical'
        elif 'malware' in classtype or 'attack' in classtype:
            return 'high'
        elif 'scan' in classtype or 'suspicious' in classtype:
            return 'medium'
        return 'low'

    def _get_tags(self, options: Dict) -> List[str]:
        """Extract tags from rule options"""
        tags = []
        if 'classtype' in options:
            tags.append(options['classtype'].lower())
        if 'reference' in options:
            tags.extend(ref.strip() for ref in options['reference'].split(','))
        if 'tag' in options:
            tags.append(options['tag'])
        return list(set(tags))  # Remove duplicates

    def _generate_rule_id(self) -> str:
        """Generate a unique rule ID"""
        self._current_rule_id += 1
        return f"suricata_{self._current_rule_id}"
