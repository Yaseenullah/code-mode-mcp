import math
from typing import Any, Awaitable, Callable


class ToolError(Exception):
    """Raised for any invalid tool call; the message is shown to the JS caller."""


def _two_numbers(args: Any) -> tuple[float, float]:
    if not isinstance(args, dict) or set(args.keys()) != {"a", "b"}:
        raise ToolError("expected exactly {a, b}")
    a, b = args["a"], args["b"]
    for v in (a, b):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            raise ToolError("a and b must be finite numbers")
    return float(a), float(b)


async def add(args: Any) -> float:
    a, b = _two_numbers(args)
    return a + b


async def subtract(args: Any) -> float:
    a, b = _two_numbers(args)
    return a - b


async def multiply(args: Any) -> float:
    a, b = _two_numbers(args)
    return a * b


async def divide(args: Any) -> float:
    a, b = _two_numbers(args)
    if b == 0:
        raise ToolError("division by zero")
    return a / b


# Strict allow-list. To add a tool: write an async function above and register it here.
# The executor's JS `tools` object must also expose it (see BOOTSTRAP in executor.js).
TOOLS: dict[str, Callable[[Any], Awaitable[Any]]] = {
    "add": add,
    "subtract": subtract,
    "multiply": multiply,
    "divide": divide,
}


async def call_tool(name: Any, args: Any) -> Any:
    handler = TOOLS.get(name) if isinstance(name, str) else None
    if handler is None:
        raise ToolError(f"unknown tool: {name}")
    result = await handler(args)
    if isinstance(result, float) and not math.isfinite(result):
        raise ToolError("result is not a finite number")
    return result