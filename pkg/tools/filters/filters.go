package filters

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/vulnx/v2"
)

// Handler lists the query fields vulnx supports, for the CLI and the vulnx_fields_list MCP tool.
type Handler struct {
	client *vulnx.Client
}

// NewHandler returns a Handler for client.
func NewHandler(client *vulnx.Client) *Handler {
	return &Handler{client: client}
}

// List returns the query fields vulnx translates for SecurityContext.
func (h *Handler) List() ([]vulnx.VulnerabilityFilter, error) {
	return h.client.GetVulnerabilityFilters(context.Background())
}

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnx_fields_list",
		mcp.WithDescription("List the fields vulnx_search and vulnx_analyze accept, with examples. NOTE: Call this tool ONLY when the `agent_vulnx` tool explicitly instructs you to do so, or when the user directly requests it; otherwise do not invoke it."),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *vulnx.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filters, err := h.List()
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(filters, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: failed to marshal fields: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnx) fields:\n" + string(b)), nil
	}
}
