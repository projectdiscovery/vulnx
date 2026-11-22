package id

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/vulnx/v2"
)

type Handler struct {
	client *vulnx.Client
}

// NewHandler returns a new Handler instance
func NewHandler(client *vulnx.Client) *Handler {
	return &Handler{
		client: client,
	}
}

// Get fetches one CVE record by id.
func (h *Handler) Get(id string) (*vulnx.Vulnerability, error) {
	resp, err := h.client.GetVulnerabilityByID(context.Background(), id, nil)
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnx_get_by_id",
		mcp.WithDescription("Retrieve a full CVE record by its CVE id (only CVE records are supported). NOTE: Invoke only when `agent_vulnx` instructs or the user explicitly requests it; otherwise do not call this tool."),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("The CVE id to retrieve (e.g. 'CVE-2021-44228')."),
		),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *vulnx.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := request.RequireString("id")
		if err != nil || id == "" {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: 'id' is required and must be a string."), nil
		}
		resp, err := h.client.GetVulnerabilityByID(ctx, id, nil)
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(resp.Data, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: failed to marshal vulnerability: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnx) result for ID '" + id + "':\n" + string(b)), nil
	}
}
