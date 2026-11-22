package analyze

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/vulnx/v2"
)

// Handler counts CVEs by field values (facets).
type Handler struct {
	client *vulnx.Client
}

// NewHandler constructs a new Handler instance.
func NewHandler(client *vulnx.Client) *Handler {
	return &Handler{client: client}
}

// MaxFacetSize is the most buckets a facet returns: SecurityContext answers at most 50 per facet.
const MaxFacetSize = 50

// Params groups the parameters for faceted vulnerability analysis.
type Params struct {
	// Fields are the facets to compute, each a field name or "field=size" (e.g. "severity=5"); at most 3.
	Fields []string
	// Query is an optional field:value query that filters the CVEs counted.
	Query *string
	// FacetSize is the number of buckets for a field given without a size; 10 when nil.
	FacetSize *int
}

// Analyze counts CVEs per value of each field in params.Fields. Sizes above MaxFacetSize are capped.
func (h *Handler) Analyze(params Params) (vulnx.SearchResponse, error) {
	facets := make([]string, len(params.Fields))
	for i, f := range params.Fields {
		name, size, ok := strings.Cut(strings.ReplaceAll(f, "=", ":"), ":")
		if n, err := strconv.Atoi(strings.TrimSpace(size)); ok && err == nil && n > MaxFacetSize {
			size = strconv.Itoa(MaxFacetSize)
		}
		facets[i] = name
		if ok {
			facets[i] += ":" + size
		}
	}
	facetSize := 10
	if params.FacetSize != nil {
		facetSize = min(*params.FacetSize, MaxFacetSize)
	}
	return h.client.SearchVulnerabilities(context.Background(), vulnx.SearchParams{
		Query:      params.Query,
		TermFacets: facets,
		FacetSize:  &facetSize,
		Fields:     []string{"cve_id"},
		Limit:      vulnx.Ptr(1),
	})
}

// MCPToolSpec returns the MCP tool specification for vulnerability analysis
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnx_analyze",
		mcp.WithDescription("Aggregate vulnerabilities (ANALYZE/facets) over selected fields. NOTE: Use this tool ONLY when instructed by `agent_vulnx` or when the user explicitly asks for an analysis; do NOT call it otherwise."),
		mcp.WithArray("fields",
			mcp.Description("Up to 3 fields to count CVEs by. Example: ['severity=5', 'vendor=10']. Each entry is a field name or 'field=size' to set its bucket count (max 50)."),
			mcp.Items(map[string]any{"type": "string"}),
			mcp.Required(),
		),
		mcp.WithString("query",
			mcp.Description("Optional field:value query (terms joined by '&&'; '||' only between values of one field) that filters the CVEs counted. See 'vulnx_fields_list' for valid fields."),
		),
		mcp.WithNumber("facet_size",
			mcp.Description("Bucket count for fields given without '=size' (default 10, max 50)."),
		),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *vulnx.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fields, err := request.RequireStringSlice("fields")
		if err != nil || len(fields) == 0 {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: 'fields' is required and must be a string array."), nil
		}
		query := request.GetString("query", "")
		var queryPtr *string
		if query != "" {
			queryPtr = &query
		}
		facetSize := request.GetInt("facet_size", 0)
		var facetSizePtr *int
		if facetSize > 0 {
			facetSizePtr = &facetSize
		}
		params := Params{
			Fields:    fields,
			Query:     queryPtr,
			FacetSize: facetSizePtr,
		}
		resp, err := h.Analyze(params)
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: failed to marshal analysis result: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnx) analysis result:\n" + string(b)), nil
	}
}
