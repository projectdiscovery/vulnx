package clis

import (
	"slices"
	"testing"
)

func TestMergeFields(t *testing.T) {
	base := []string{"doc_id", "cve_id"}
	got := mergeFields(base, []string{"doc_id", "severity"})
	if want := []string{"doc_id", "cve_id", "severity"}; !slices.Equal(got, want) {
		t.Errorf("mergeFields = %v, want %v", got, want)
	}
	if len(base) != 2 {
		t.Errorf("mergeFields mutated base: %v", base)
	}
}
