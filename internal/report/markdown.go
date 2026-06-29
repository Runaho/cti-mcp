package report

import (
	"fmt"
	"strings"
	"time"
)

// trimMarkdown trims a string to at most n runes, appending an ellipsis if cut.
func trimMarkdown(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}

// escapePipe replaces pipe characters that would break markdown tables.
func escapePipe(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// RenderMarkdown renders a CTIReport as a pure-Go Markdown document.
// No external library is used; the output is plain CommonMark.
func RenderMarkdown(r *CTIReport) (string, error) {
	if r == nil {
		return "", fmt.Errorf("nil report")
	}

	var b strings.Builder

	// Header
	b.WriteString("# CTI Threat Report\n\n")

	// Generated timestamp - prefer RFC3339 for machine-friendly format.
	generated := r.Meta.GeneratedAt
	if generated == "" {
		generated = time.Now().UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(&b, "Generated: %s\n", generated)

	fmt.Fprintf(&b, "Window: %d hours\n", r.Meta.WindowHours)

	if r.Meta.Sources != "" {
		fmt.Fprintf(&b, "Sources: %s\n", r.Meta.Sources)
	}
	b.WriteString("\n")

	// Stats
	b.WriteString("## Stats\n\n")
	total := r.Meta.P1 + r.Meta.P2 + r.Meta.P3
	fmt.Fprintf(&b, "- P1 CRITICAL: %d\n", r.Meta.P1)
	fmt.Fprintf(&b, "- P2 HIGH: %d\n", r.Meta.P2)
	fmt.Fprintf(&b, "- P3 STANDARD: %d\n", r.Meta.P3)
	fmt.Fprintf(&b, "- TOTAL: %d\n", total)
	b.WriteString("\n")

	// KEV Recent
	if len(r.KEVRecent) > 0 {
		fmt.Fprintf(&b, "## KEV Recent (%d entries)\n\n", len(r.KEVRecent))
		for _, k := range r.KEVRecent {
			dateAdded := k.DateAdded
			if dateAdded == "" {
				dateAdded = "unknown"
			}
			cveID := k.CVEID
			if cveID == "" {
				cveID = "unknown"
			}
			vendor := escapePipe(k.VendorProduct)
			if vendor == "" {
				vendor = "unknown"
			}
			action := strings.TrimSpace(k.RequiredAction)
			if action == "" {
				action = "Apply mitigations per vendor guidance"
			}
			fmt.Fprintf(&b, "- %s | %s | %s | %s\n",
				dateAdded, cveID, vendor, action)
		}
		b.WriteString("\n")
	}

	// Sectors
	if len(r.Sectors) > 0 {
		b.WriteString("## Sectors\n\n")
		for _, s := range r.Sectors {
			if len(s.CVEs) == 0 {
				continue
			}
			fmt.Fprintf(&b, "### %s\n\n", s.Name)
			for _, c := range s.CVEs {
				severity := c.Severity
				if severity == "" {
					severity = "UNKNOWN"
				}
				cveID := c.ID
				if cveID == "" {
					cveID = "unknown"
				}
				title := trimMarkdown(c.Title, 80)
				if title == "" {
					title = "(no title)"
				}
				title = escapePipe(title)

				link := c.GHSAURL
				if link == "" {
					link = c.NVDURL
				}
				if link == "" && strings.HasPrefix(cveID, "CVE-") {
					link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
				}

				if link != "" {
					fmt.Fprintf(&b, "- %s | %s | %s | [more](%s)\n",
						severity, cveID, title, link)
				} else {
					fmt.Fprintf(&b, "- %s | %s | %s\n",
						severity, cveID, title)
				}
			}
			b.WriteString("\n")
		}
	}

	return b.String(), nil
}