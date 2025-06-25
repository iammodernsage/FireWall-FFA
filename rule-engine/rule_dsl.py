import re
import inspect
from typing import Any, Dict, List, Optional, Callable, Union
from functools import wraps
import ipaddress
from datetime import datetime, timedelta
import pytz
from concurrent.freq import FrequencyTracker

class RuleDSL:
    """Domain-Specific Language for writing custom WAF rules"""

    def __init__(self, parser=None):
        self.parser = parser
        self._custom_functions = {}
        self._rate_limiters = {}
        self._init_builtins()

    def _init_builtins(self):
        """Register built-in DSL functions"""
        self.register_function('contains', self._op_contains)
        self.register_function('equals', self._op_equals)
        self.register_function('matches', self._op_matches)
        self.register_function('startsWith', self._op_starts_with)
        self.register_function('endsWith', self._op_ends_with)
        self.register_function('regex', self._op_regex)
        self.register_function('ipInRange', self._op_ip_in_range)
        self.register_function('in', self._op_in)
        self.register_function('gt', self._op_gt)
        self.register_function('lt', self._op_lt)
        self.register_function('rateLimit', self._op_rate_limit)
        self.register_function('geoMatch', self._op_geo_match)
        self.register_function('timeWindow', self._op_time_window)

    def register_function(self, name: str, func: Callable):
        """Register a custom DSL function"""
        if not callable(func):
            raise ValueError(f"Function {name} must be callable")

        sig = inspect.signature(func)
        if len(sig.parameters) < 2:
            raise ValueError(f"Function {name} must accept at least 2 parameters (context, value)")

        self._custom_functions[name] = func

    def function(self, name: str):
        """Decorator to register DSL functions"""
        def decorator(func):
            self.register_function(name, func)
            return func
        return decorator

    def compile_rule(self, dsl_rule: Union[str, Dict]) -> Dict:
        """Compile a DSL rule into standard rule format"""
        if isinstance(dsl_rule, str):
            try:
                # Try parsing as JSON if string
                dsl_rule = json.loads(dsl_rule)
            except json.JSONDecodeError:
                raise ValueError("DSL rule must be valid JSON or dict")

        if not isinstance(dsl_rule, dict):
            raise ValueError("DSL rule must be a dictionary")

        # Convert DSL conditions to standard format
        if 'when' in dsl_rule:
            dsl_rule['condition'] = self._convert_dsl_condition(dsl_rule['when'])
            del dsl_rule['when']

        # Set defaults
        dsl_rule.setdefault('action', 'block')
        dsl_rule.setdefault('enabled', True)
        dsl_rule.setdefault('severity', 'medium')

        if self.parser:
            if not self.parser.validate_rule(dsl_rule):
                raise ValueError("Compiled rule failed validation")

        return dsl_rule

    def _convert_dsl_condition(self, condition: Any) -> Dict:
        """Convert DSL condition to standard format"""
        if isinstance(condition, dict):
            if len(condition) != 1:
                raise ValueError("DSL condition dict must have exactly one key")

            op, args = next(iter(condition.items()))

            if op in ['and', 'or', 'not']:
                # Handle logical operators
                if op == 'not':
                    if not isinstance(args, (dict, list)):
                        raise ValueError("NOT operator requires a condition or list")
                    return {'not': self._convert_dsl_condition(args)}
                else:
                    if not isinstance(args, list):
                        raise ValueError(f"{op.upper()} operator requires a list of conditions")
                    return {op: [self._convert_dsl_condition(c) for c in args]}
            else:
                # Handle comparison operators
                if not isinstance(args, dict) or 'field' not in args:
                    raise ValueError(f"Operator {op} requires field and value parameters")

                converted = {
                    'field': args['field'],
                    'operator': op,
                    'value': args.get('value')
                }

                # Handle special cases
                if 'timeout' in args:
                    converted['timeout'] = args['timeout']
                if 'threshold' in args:
                    converted['threshold'] = args['threshold']

                return converted
        elif isinstance(condition, list):
            return {'and': [self._convert_dsl_condition(c) for c in condition]}
        else:
            raise ValueError(f"Invalid DSL condition type: {type(condition)}")

    def evaluate(self, rule: Dict, context: Dict) -> bool:
        """Evaluate a rule using the DSL processor"""
        if 'when' in rule:
            condition = self._convert_dsl_condition(rule['when'])
            return self._evaluate_condition(condition, context)
        elif 'condition' in rule:
            return self._evaluate_condition(rule['condition'], context)
        else:
            raise ValueError("Rule has no conditions to evaluate")

    def _evaluate_condition(self, condition: Dict, context: Dict) -> bool:
        """Evaluate a single condition"""
        if 'and' in condition:
            return all(self._evaluate_condition(c, context) for c in condition['and'])
        elif 'or' in condition:
            return any(self._evaluate_condition(c, context) for c in condition['or'])
        elif 'not' in condition:
            return not self._evaluate_condition(condition['not'], context)
        else:
            return self._evaluate_operator(
                condition['operator'],
                condition.get('field'),
                condition.get('value'),
                context,
                condition
            )

    def _evaluate_operator(self, op: str, field: str, value: Any, context: Dict, params: Dict) -> bool:
        """Evaluate a single operator"""
        if op not in self._custom_functions:
            raise ValueError(f"Unknown operator: {op}")

        context_value = context.get(field) if field else None
        return self._custom_functions[op](context, context_value, value, params)

    # Built-in operator implementations
    def _op_contains(self, context: Dict, context_value: Any, value: Any, params: Dict) -> bool:
        if context_value is None:
            return False
        if isinstance(context_value, str) and isinstance(value, str):
            return value.lower() in context_value.lower()
        elif isinstance(context_value, list):
            return value in context_value
        return False

    def _op_equals(self, context: Dict, context_value: Any, value: Any, params: Dict) -> bool:
        return context_value == value

    def _op_matches(self, context: Dict, context_value: Any, pattern: str, params: Dict) -> bool:
        if context_value is None:
            return False
        try:
            return bool(re.search(pattern, str(context_value), re.IGNORECASE)
        except re.error:
            return False

    def _op_starts_with(self, context: Dict, context_value: Any, prefix: str, params: Dict) -> bool:
        if context_value is None:
            return False
        return str(context_value).lower().startswith(prefix.lower())

    def _op_ends_with(self, context: Dict, context_value: Any, suffix: str, params: Dict) -> bool:
        if context_value is None:
            return False
        return str(context_value).lower().endswith(suffix.lower())

    def _op_regex(self, context: Dict, context_value: Any, pattern: str, params: Dict) -> bool:
        return self._op_matches(context, context_value, pattern, params)

    def _op_ip_in_range(self, context: Dict, context_value: Any, ip_range: Union[str, List], params: Dict) -> bool:
        if context_value is None:
            return False
        try:
            ip = ipaddress.ip_address(str(context_value))
            if isinstance(ip_range, str):
                return ip in ipaddress.ip_network(ip_range, strict=False)
            elif isinstance(ip_range, list):
                return any(ip in ipaddress.ip_network(r, strict=False) for r in ip_range)
        except ValueError:
            return False
        return False

    def _op_in(self, context: Dict, context_value: Any, values: List, params: Dict) -> bool:
        return context_value in values if values else False

    def _op_gt(self, context: Dict, context_value: Any, value: Any, params: Dict) -> bool:
        try:
            return float(context_value) > float(value)
        except (ValueError, TypeError):
            return False

    def _op_lt(self, context: Dict, context_value: Any, value: Any, params: Dict) -> bool:
        try:
            return float(context_value) < float(value)
        except (ValueError, TypeError):
            return False

    def _op_rate_limit(self, context: Dict, context_value: Any, config: Dict, params: Dict) -> bool:
        """Rate limiting operator"""
        if not all(k in config for k in ['field', 'threshold', 'window']):
            raise ValueError("rateLimit requires field, threshold and window config")

        tracker_key = f"{config['field']}:{context.get(config['field'])}"

        if tracker_key not in self._rate_limiters:
            self._rate_limiters[tracker_key] = FrequencyTracker(
                threshold=config['threshold'],
                window=timedelta(seconds=config['window'])
            )

        tracker = self._rate_limiters[tracker_key]
        return tracker.hit()

    def _op_geo_match(self, context: Dict, context_value: Any, countries: List[str], params: Dict) -> bool:
        """Geographic matching operator"""
        ip = context_value or context.get('source.ip')
        if not ip:
            return False

        # In a real implementation, you would use a geo-IP database here
        country = self._lookup_country(ip)  # Mock function
        return country in countries

    def _op_time_window(self, context: Dict, context_value: Any, window: Dict, params: Dict) -> bool:
        """Time window operator"""
        if not all(k in window for k in ['start', 'end']):
            raise ValueError("timeWindow requires start and end times")

        now = datetime.now(pytz.utc)
        start = self._parse_time(window['start'])
        end = self._parse_time(window['end'])

        if start <= end:
            return start <= now <= end
        else:
            # Crosses midnight
            return now >= start or now <= end

    def _lookup_country(self, ip: str) -> str:
        """Mock geo-IP lookup - replace with real implementation"""
        return "US"  # Example mock

    def _parse_time(self, time_str: str) -> datetime:
        """Parse time string (supports 'HH:MM' or 'HH:MM:SS')"""
        try:
            hour, minute = map(int, time_str.split(':'))
            second = 0
            if ':' in time_str[time_str.index(':')+1:]:
                hour, minute, second = map(int, time_str.split(':'))
            now = datetime.now(pytz.utc)
            return now.replace(hour=hour, minute=minute, second=second, microsecond=0)
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid time format: {time_str}")

class FrequencyTracker:
    """Helper class for rate limiting"""
    def __init__(self, threshold: int, window: timedelta):
        self.threshold = threshold
        self.window = window
        self.hits = []

    def hit(self) -> bool:
        """Record a hit and return True if threshold exceeded"""
        now = datetime.now(pytz.utc)
        self.hits.append(now)

        # Remove hits outside the window
        cutoff = now - self.window
        self.hits = [h for h in self.hits if h >= cutoff]

        return len(self.hits) > self.threshold
