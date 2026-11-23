package analyze

import (
	"context"
	"strconv"
	"strings"

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
