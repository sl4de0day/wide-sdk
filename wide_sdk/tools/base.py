import inspect
from typing import Callable, Dict, Any, Optional
from ..types import ToolDefinition, ToolResult

class BaseTool:
    def __init__(self, definition: ToolDefinition, handler: Callable[..., ToolResult]) -> None:
        self.definition = definition
        self.handler = handler

    def execute(self, params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
        return self.handler(params, context)

def tool(name: Optional[str] = None, description: Optional[str] = None) -> Callable[[Callable], BaseTool]:
    def decorator(fn: Callable) -> BaseTool:
        tool_name = name or fn.__name__
        tool_desc = description or (inspect.getdoc(fn) or tool_name)
        sig = inspect.signature(fn)

        properties = {}
        required = []

        for p_name, param in sig.parameters.items():
            if p_name in ("context", "self"):
                continue

            param_type = "string"
            if param.annotation == int:
                param_type = "number"
            elif param.annotation == bool:
                param_type = "boolean"
            elif param.annotation == dict:
                param_type = "object"
            elif param.annotation == list:
                param_type = "array"

            properties[p_name] = {
                "type": param_type,
                "description": f"Parameter {p_name}"
            }

            if param.default == inspect.Parameter.empty:
                required.append(p_name)

        definition = ToolDefinition(
            name=tool_name,
            description=tool_desc.strip(),
            parameters={
                "type": "object",
                "properties": properties,
                "required": required
            }
        )

        def runner(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
            kwargs = {k: v for k, v in params.items() if k in sig.parameters}
            if "context" in sig.parameters:
                kwargs["context"] = context
            return fn(**kwargs)

        return BaseTool(definition, runner)
    return decorator
