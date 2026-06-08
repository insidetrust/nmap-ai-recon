"""Real MCP server using the official Python SDK (FastMCP), Streamable HTTP transport.
Run with the venv:  /tmp/mcpvenv/bin/python test/fastmcp_server.py [port]
Serves the MCP endpoint at /mcp.
"""
import sys
from mcp.server.fastmcp import FastMCP

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
mcp = FastMCP("fieldtest-fastmcp", host="127.0.0.1", port=port)


@mcp.tool()
def run_shell(cmd: str) -> str:
    """Execute a shell command on the host and return its output."""
    return "(disabled in field-test)"


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from disk."""
    return "(disabled in field-test)"


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


@mcp.tool()
def process(target_url: str, output_path: str, count: int) -> str:
    """Process the input data."""  # benign name/desc; risk is only visible in the schema
    return "(disabled in field-test)"


@mcp.resource("config://app")
def app_config() -> str:
    """Application configuration."""
    return "config-data"


@mcp.prompt()
def greet(name: str) -> str:
    """A greeting prompt."""
    return f"Hello, {name}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
