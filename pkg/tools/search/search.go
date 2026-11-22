package search

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/vulnx/v2"
)

// Handler runs searches for the CLI and the vulnx_search MCP tool.
type Handler struct {
	client *vulnx.Client
}

// NewHandler returns a Handler that searches with client.
func NewHandler(client *vulnx.Client) *Handler {
	return &Handler{client: client}
}

// Search runs one search with params.
func (h *Handler) Search(params vulnx.SearchParams) (vulnx.SearchResponse, error) {
	return h.client.SearchVulnerabilities(context.Background(), params)
}

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnx_search",
		mcp.WithDescription("Search CVEs (SecurityContext) with field:value terms joined by '&&'; '||' only between values of one field (severity:critical || severity:high); up to 5 keywords; one vendor or product. NOTE: Use this tool ONLY when `agent_vulnx` explicitly instructs you or when the user directly asks for a search; otherwise do not invoke it."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("field:value query (e.g. 'severity:critical && vendor:atlassian && is_kev:true'). Use only fields from 'vulnx_fields_list'."),
		),
		mcp.WithNumber("limit",
			mcp.Description("Results per call (default 5, 1-100)."),
		),
		mcp.WithNumber("offset",
			mcp.Description("Starting index for pagination (default 0); offset + limit can be at most 1000."),
		),
		mcp.WithArray("fields",
			mcp.Description("Optional list of fields to include in the response. Omit for defaults, [] for full payload."),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("sort_asc",
			mcp.Description("Field name to sort ascending."),
		),
		mcp.WithString("sort_desc",
			mcp.Description("Field name to sort descending."),
		),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *vulnx.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := request.RequireString("query")
		if err != nil || query == "" {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: 'query' is required and must be a string."), nil
		}
		limit := min(request.GetInt("limit", 5), 100)
		offset := request.GetInt("offset", 0)
		if limit < 1 || offset < 0 {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: 'limit' must be 1-100 and 'offset' must not be negative."), nil
		}

		// Prepare base search parameters
		params := vulnx.SearchParams{
			Query:  &query,
			Limit:  &limit,
			Offset: &offset,
		}

		// Handle optional 'fields' array
		fields := request.GetStringSlice("fields", nil)
		defaultFields := []string{"cve_id", "name", "remediation", "cve_created_at", "poc_count", "updated_at", "impact", "description", "severity", "cvss_score", "epss_score", "is_kev", "is_vkev", "is_oss", "is_patch_available", "is_poc", "is_remote"}
		switch {
		case fields == nil:
			// No parameter provided – apply defaults to reduce payload size
			params.Fields = defaultFields
		case len(fields) == 0:
			// Explicit empty array means no field filtering (full document)
		default:
			params.Fields = fields
		}

		// Sorting parameters (optional)
		sortAsc := request.GetString("sort_asc", "")
		if sortAsc != "" {
			params.SortAsc = &sortAsc
		}
		sortDesc := request.GetString("sort_desc", "")
		if sortDesc != "" {
			params.SortDesc = &sortDesc
		}

		resp, err := h.client.SearchVulnerabilities(ctx, params)
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: failed to marshal search result: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnx) search result:\n" + string(b)), nil
	}
}
