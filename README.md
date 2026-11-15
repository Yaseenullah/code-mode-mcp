
# Secure Code Mode MCP Server

A sandboxed **Code Mode MCP server** that enables AI agents to execute multi-step JavaScript workflows through a single `run_code` tool call.

Instead of making multiple individual MCP tool calls, an agent can write JavaScript that invokes tools, performs loops, applies conditional logic, and combines results within a single execution.

---

## Try the Live Server

The MCP server is deployed and accessible through **Streamable HTTP**.

**MCP Endpoint:** https://code-mode-mcp.onrender.com/mcp

### Run using MCP Inspector

Interact with the deployed MCP server using the official [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

**Prerequisites**
- Node.js 22 or later
- npm / npx

### 1. Launch MCP Inspector

Run the following command in your terminal:

```bash
npx -y @modelcontextprotocol/inspector \
  --server-url https://code-mode-mcp.onrender.com/mcp \
  --transport http
```

### 2. Connect and Test

Once MCP Inspector launches:

1. Open the local Inspector interface.
2. Click **Connect** if the server is not connected automatically.
3. Navigate to the **Tools** section.
4. Select `run_code`.
5. Submit JavaScript code and inspect the execution results.

---

