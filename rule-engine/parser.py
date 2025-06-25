import re
import yaml
import json
from typing import Dict, List, Any, Union, Optional
from pathlib import Path
import ipaddress
import fnmatch
import logging
from datetime import datetime
import jsonschema
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RuleParser:
    """Rule parser with validation and transformation capabilities (note: still working on making it more reliable)"""

    # Schema for rule validation
    RULE_SCHEMA = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "pattern": "^[a-zA-Z0-9_-]+$"},
            "description": {"type": "string"},
            "author": {"type": "string"},
            "created": {"type": "string", "format": "date-time"},
            "modified": {"type": "string", "format": "date-time"},
            "tags": {"type": "array", "items": {"type": "string"}},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "action": {"type": "string", "enum": ["allow", "block", "challenge", "log"]},
            "condition": {"type": "object"},
            "enabled": {"type": "boolean"},
            "source": {"type": "string"}
        },
        "required": ["id", "action", "condition"],
        "additionalProperties": False
    }

    CONDITION_SCHEMA = {
        "type": "object",
        "properties": {
            "field": {"type": "string"},
            "operator": {
                "type": "string",
                "enum": [
                    "equals", "contains", "matches", "startsWith", "endsWith",
                    "in", "notIn", "regex", "ipInRange", "greaterThan",
                    "lessThan", "exists", "notExists"
                ]
            },
            "value": {},
            "and": {"type": "array", "items": {"$ref": "#/definitions/condition"}},
            "or": {"type": "array", "items": {"$ref": "#/definitions/condition"}},
            "not": {"$ref": "#/definitions/condition"}
        },
        "definitions": {
            "condition": {
                "type": "object",
                "properties": {
                    "field": {"type": "string"},
                    "operator": {"type": "string"},
                    "value": {},
                    "and": {"type": "array", "items": {"$ref": "#/definitions/condition"}},
                    "or": {"type": "array", "items": {"$ref": "#/definitions/condition"}},
                    "not": {"$ref": "#/definitions/condition"}
                }
            }
        },
        "anyOf": [
            {"required": ["field", "operator", "value"]},
            {"required": ["and"]},
            {"required": ["or"]},
            {"required": ["not"]}
        ],
        "additionalProperties": False
    }

    def __init__(self):
        self._validator = jsonschema.Draft7Validator(self.RULE_SCHEMA)
        self._condition_validator = jsonschema.Draft7Validator(self.CONDITION_SCHEMA)
        self._compiled_patterns = {}

    @lru_cache(maxsize=1024)
    def _compile_pattern(self, pattern: str) -> re.Pattern:
        """Compile and cache regex patterns"""
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern}': {str(e)}")
            raise ValueError(f"Invalid regex pattern: {str(e)}")

    def _validate_ip(self, ip: str) -> bool:
        """Validate an IP address or CIDR (refer wiki for more) range"""
        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            return False

    def _validate_condition(self, condition: Dict[str, Any]) -> None:
        """Validate a single condition"""
        try:
            self._condition_validator.validate(condition)
        except jsonschema.ValidationError as e:
            logger.error(f"Condition validation failed: {str(e)}")
            raise ValueError(f"Invalid condition: {str(e)}")

        # Type-specific validation
        operator = condition.get("operator")
        value = condition.get("value")

        if operator in ["regex", "matches"]:
            if not isinstance(value, str):
                raise ValueError("Regex pattern must be a string")
            self._compile_pattern(value)  # Test compile

        elif operator == "ipInRange":
            if isinstance(value, str):
                if not self._validate_ip(value):
                    raise ValueError(f"Invalid IP/CIDR: {value}")
            elif isinstance(value, list):
                for ip in value:
                    if not self._validate_ip(ip):
                        raise ValueError(f"Invalid IP/CIDR in list: {ip}")
            else:
                raise ValueError("IP range must be string or list")

    def validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate a rule against the schema"""
        try:
            # Validate basic structure
            self._validator.validate(rule)

            # Validate condition tree recursively
            self._validate_condition_tree(rule["condition"])

            return True
        except (jsonschema.ValidationError, ValueError) as e:
            logger.error(f"Rule validation failed: {str(e)}")
            return False

    def _validate_condition_tree(self, condition: Dict[str, Any]) -> None:
        """Recursively validate condition tree"""
        self._validate_condition(condition)

        if "and" in condition:
            for sub_cond in condition["and"]:
                self._validate_condition_tree(sub_cond)

        if "or" in condition:
            for sub_cond in condition["or"]:
                self._validate_condition_tree(sub_cond)

        if "not" in condition:
            self._validate_condition_tree(condition["not"])

    def parse_rule_file(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Parse a rule file (YAML or JSON)"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {file_path}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix.lower() in ('.yaml', '.yml'):
                    rules = yaml.safe_load(f)
                elif path.suffix.lower() == '.json':
                    rules = json.load(f)
                else:
                    raise ValueError(f"Unsupported file format: {path.suffix}")

            if not isinstance(rules, list):
                rules = [rules]


            validated_rules = []
            for rule in rules:
                if self.validate_rule(rule):
                    validated_rules.append(self._normalize_rule(rule))
                else:
                    logger.warning(f"Skipping invalid rule in {file_path}")

            return validated_rules

        except (yaml.YAMLError, json.JSONDecodeError) as e:
            logger.error(f"Error parsing rule file {file_path}: {str(e)}")
            raise ValueError(f"Invalid rule file format: {str(e)}")

    def _normalize_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:

        normalized = {
            "id": rule["id"],
            "action": rule["action"],
            "condition": self._normalize_condition(rule["condition"]),
            "description": rule.get("description", ""),
            "author": rule.get("author", "unknown"),
            "created": rule.get("created", datetime.utcnow().isoformat()),
            "modified": rule.get("modified", datetime.utcnow().isoformat()),
            "tags": rule.get("tags", []),
            "severity": rule.get("severity", "medium"),
            "enabled": rule.get("enabled", True),
            "source": rule.get("source", "file")
        }
        return normalized

    def _normalize_condition(self, condition: Dict[str, Any]) -> Dict[str, Any]:

        normalized = condition.copy()

        if "and" in condition:
            normalized["and"] = [self._normalize_condition(c) for c in condition["and"]]
        if "or" in condition:
            normalized["or"] = [self._normalize_condition(c) for c in condition["or"]]
        if "not" in condition:
            normalized["not"] = self._normalize_condition(condition["not"])

        return normalized

    def load_rules_from_dir(self, dir_path: Union[str, Path]) -> Dict[str, Dict[str, Any]]:

        path = Path(dir_path)
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        rules = {}
        for rule_file in path.glob("*.yaml"):
            try:
                for rule in self.parse_rule_file(rule_file):
                    if rule["id"] in rules:
                        logger.warning(f"Duplicate rule ID: {rule['id']}")
                    rules[rule["id"]] = rule
            except ValueError as e:
                logger.error(f"Error loading {rule_file}: {str(e)}")
                continue

        for rule_file in path.glob("*.json"):
            try:
                for rule in self.parse_rule_file(rule_file):
                    if rule["id"] in rules:
                        logger.warning(f"Duplicate rule ID: {rule['id']}")
                    rules[rule["id"]] = rule
            except ValueError as e:
                logger.error(f"Error loading {rule_file}: {str(e)}")
                continue

        return rules

    def match_condition(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:

        if "and" in condition:
            return all(self.match_condition(c, context) for c in condition["and"])
        if "or" in condition:
            return any(self.match_condition(c, context) for c in condition["or"])
        if "not" in condition:
            return not self.match_condition(condition["not"], context)

        field = condition["field"]
        operator = condition["operator"]
        value = condition["value"]
        context_value = context.get(field)

        # Handle field existence checks
        if operator == "exists":
            return field in context
        if operator == "notExists":
            return field not in context

        # Handle cases where field doesn't exist
        if context_value is None:
            return False

        # Perform operator-specific comparisons
        try:
            if operator == "equals":
                return context_value == value
            elif operator == "contains":
                if isinstance(context_value, str) and isinstance(value, str):
                    return value.lower() in context_value.lower()
                elif isinstance(context_value, list):
                    return value in context_value
            elif operator in ["matches", "regex"]:
                pattern = self._compile_pattern(value)
                return bool(pattern.search(str(context_value)))
            elif operator == "startsWith":
                return str(context_value).lower().startswith(str(value).lower())
            elif operator == "endsWith":
                return str(context_value).lower().endswith(str(value).lower())
            elif operator == "in":
                return context_value in value if isinstance(value, list) else False
            elif operator == "notIn":
                return context_value not in value if isinstance(value, list) else True
            elif operator == "ipInRange":
                ip = ipaddress.ip_address(str(context_value))
                if isinstance(value, str):
                    network = ipaddress.ip_network(value, strict=False)
                    return ip in network
                elif isinstance(value, list):
                    return any(ip in ipaddress.ip_network(v, strict=False) for v in value)
            elif operator == "greaterThan":
                return float(context_value) > float(value)
            elif operator == "lessThan":
                return float(context_value) < float(value)
        except (ValueError, AttributeError) as e:
            logger.warning(f"Error evaluating condition: {str(e)}")
            return False

        return False

    def evaluate_rule(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate a rule against context data"""

        if not rule.get("enabled", True):
            return False

        try:
            return self.match_condition(rule["condition"], context)
        except Exception as e:
            logger.error(f"Error evaluating rule {rule['id']}: {str(e)}")
            return False
