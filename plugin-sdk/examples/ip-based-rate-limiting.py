from collections import defaultdict
from datetime import datetime, timedelta
from plugin_interface import *

@plugin_metadata(PluginMetadata(
    name="RateLimiter",
    plugin_type=PluginType.PRE_PROCESSOR,
    version="1.1",
    description="Enforces request rate limits",
    config_schema={
        "type": "object",
        "properties": {
            "requests_per_minute": {"type": "integer", "minimum": 1},
            "block_duration": {"type": "integer", "minimum": 1}
        },
        "required": ["requests_per_minute"]
    }
))
class RateLimiterPlugin(PreProcessorPlugin):
    def initialize(self):
        self.request_counts = defaultdict(int)
        self.blocked_ips = {}
        self.window_start = datetime.now()

    def process(self, request: RequestContext, response: ResponseContext, phase: PluginPhase) -> Optional[ResponseContext]:
        if phase != PluginPhase.REQUEST_HEADERS:
            return None

        now = datetime.now()
        ip = request.remote_ip

        # Reset counters if window expired
        if (now - self.window_start) > timedelta(minutes=1):
            self.request_counts.clear()
            self.window_start = now

        # Check if IP is blocked
        if ip in self.blocked_ips and now < self.blocked_ips[ip]:
            response.set_block("Rate limit exceeded", 429)
            return response

        # Increment count and check limit
        self.request_counts[ip] += 1
        if self.request_counts[ip] > self.config["requests_per_minute"]:
            block_duration = timedelta(seconds=self.config.get("block_duration", 60))
            self.blocked_ips[ip] = now + block_duration
            response.set_block("Rate limit exceeded", 429)
            return response

        return None
