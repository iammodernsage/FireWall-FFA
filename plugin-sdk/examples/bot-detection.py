import user_agents
from plugin_interface import *

@plugin_metadata(PluginMetadata(
    name="BotDetector",
    plugin_type=PluginType.PRE_PROCESSOR,
    version="1.4",
    description="Detects and blocks bots/crawlers",
    config_schema={
        "type": "object",
        "properties": {
            "block_known_bots": {"type": "boolean", "default": True},
            "challenge_suspicious": {"type": "boolean", "default": False},
            "whitelist": {
                "type": "array",
                "items": {"type": "string"}
            }
        }
    },
    requirements=["user-agents"]
))
class BotDetectorPlugin(PreProcessorPlugin):
    def process(self, request: RequestContext, response: ResponseContext, phase: PluginPhase) -> Optional[ResponseContext]:
        if phase == PluginPhase.REQUEST_HEADERS and "User-Agent" in request.headers:
            ua = request.headers["User-Agent"]

            # Check whitelist first
            if any(wl in ua for wl in self.config.get("whitelist", [])):
                return None

            # Parse user agent
            parsed = user_agents.parse(ua)

            if self.config.get("block_known_bots", True) and parsed.is_bot:
                response.set_block("Automated traffic not allowed", 403)
                return response

            if self.config.get("challenge_suspicious", False) and not parsed.is_bot and not parsed.is_mobile and not parsed.is_pc:
                response.action = "challenge"
                return response

        return None
