from plugin_interface import *

@plugin_metadata(PluginMetadata(
    name="GeoBlocker",
    plugin_type=PluginType.PRE_PROCESSOR,
    version="1.0",
    description="Blocks requests from specific countries",
    config_schema={
        "type": "object",
        "properties": {
            "blocked_countries": {
                "type": "array",
                "items": {"type": "string", "pattern": "^[A-Z]{2}$"},
                "default": []
            },
            "message": {"type": "string"}
        },
        "required": ["blocked_countries"]
    }
))
class GeoBlockerPlugin(PreProcessorPlugin):
    def process(self, request: RequestContext, response: ResponseContext, phase: PluginPhase) -> Optional[ResponseContext]:
        if phase == PluginPhase.REQUEST_HEADERS:
            country = request.headers.get("X-Country-Code", "")
            if country in self.config["blocked_countries"]:
                msg = self.config.get("message", f"Access from {country} is blocked")
                response.set_block(msg, 403)
                return response
        return None
