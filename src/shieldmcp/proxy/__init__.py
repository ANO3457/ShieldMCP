"""ShieldMCP transport proxies."""

from .interceptor import StdioProxy

__all__ = ["StdioProxy"]

try:
    from .sse_proxy import SSEProxy as SSEProxy
    __all__.append("SSEProxy")
except ImportError:
    pass
