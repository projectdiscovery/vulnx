package renderer

import (
	"github.com/projectdiscovery/vulnx/v2"
	"github.com/projectdiscovery/vulnx/v2/internal/termtext"
)

// LayoutLine represents a single line in the layout configuration
type LayoutLine struct {
	Line   int      `json:"line"`
	Format string   `json:"format"`
	OmitIf []string `json:"omit_if"`
}

// Entry represents a vulnerability entry with all fields needed for rendering
type Entry struct {
	DocID            string               `json:"doc_id"`
	Name             string               `json:"name"`
	Severity         string               `json:"severity"`
	Author           []string             `json:"author"`
	AgeInDays        int                  `json:"age_in_days"`
	EpssScore        float64              `json:"epss_score"`
	CvssScore        float64              `json:"cvss_score"`
	Exposure         *vulnx.VulnExposure  `json:"exposure"`
	AffectedProducts []*vulnx.ProductInfo `json:"affected_products"`
	IsPatchAvailable bool                 `json:"is_patch_available"`
	PocCount         int                  `json:"poc_count"`
	IsKev            bool                 `json:"is_kev"`
	Kev              []*vulnx.KevInfo     `json:"kev"`
	IsTemplate       bool                 `json:"is_template"`
	H1               *vulnx.H1Stats       `json:"h1"`
	Tags             []string             `json:"tags"`
	Pocs             []*vulnx.POC         `json:"pocs"`
	Citations        []*vulnx.Citation    `json:"citations"`
	Description      string               `json:"description"`
	Impact           string               `json:"impact"`
	Remediation      string               `json:"remediation"`
	TemplateURI      string               `json:"template_uri"`
	TemplateRaw      string               `json:"template_raw"`
}

// FromVulnerability converts a vulnx.Vulnerability to an Entry. Text from the API is cleaned of control and
// bidi characters, since it is printed to a terminal; v is not modified.
func FromVulnerability(v *vulnx.Vulnerability) *Entry {
	if v == nil {
		return nil
	}
	c := termtext.Clean
	entry := &Entry{
		DocID:            c(v.DocID),
		Name:             c(v.Name),
		Severity:         c(v.Severity),
		Author:           cleanAll(v.Author),
		AgeInDays:        v.AgeInDays,
		EpssScore:        v.EpssScore,
		CvssScore:        v.CvssScore,
		Exposure:         v.Exposure,
		IsPatchAvailable: v.IsPatchAvailable,
		PocCount:         v.PocCount,
		IsKev:            v.IsKev,
		IsTemplate:       v.IsTemplate,
		H1:               v.H1,
		Tags:             cleanAll(v.Tags),
		Description:      c(v.Description),
		Impact:           c(v.Impact),
		Remediation:      c(v.Remediation),
		TemplateURI:      c(v.URI),
		TemplateRaw:      c(v.Raw),
	}
	for _, p := range v.AffectedProducts {
		if p != nil {
			cp := *p
			cp.Vendor, cp.Product = c(p.Vendor), c(p.Product)
			entry.AffectedProducts = append(entry.AffectedProducts, &cp)
		}
	}
	for _, k := range v.Kev {
		if k != nil {
			ck := *k
			ck.Source = c(k.Source)
			entry.Kev = append(entry.Kev, &ck)
		}
	}
	for _, p := range v.Pocs {
		if p != nil {
			cp := *p
			cp.URL, cp.Source = c(p.URL), c(p.Source)
			entry.Pocs = append(entry.Pocs, &cp)
		}
	}
	for _, ct := range v.Citations {
		if ct != nil {
			cc := *ct
			cc.URL, cc.Source, cc.Tags = c(ct.URL), c(ct.Source), cleanAll(ct.Tags)
			entry.Citations = append(entry.Citations, &cc)
		}
	}
	return entry
}

func cleanAll(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = termtext.Clean(s)
	}
	return out
}
