package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"
)

// BuildReport queries the database and constructs a CTIReport suitable for HTML rendering.
func BuildReport(db *store.Store, hours int) (*CTIReport, error) {
	if hours <= 0 {
		hours = 24
	}

	// Query all CVEs (no time filter for now — report shows everything in cache)
	cves, err := store.QueryCVEs(db.DB(), "", 0, 500)
	if err != nil {
		return nil, fmt.Errorf("query cves: %w", err)
	}

	// Query KEV entries (last 30 days)
	kevEntries, err := store.QueryKEV(db.DB(), 30, 200)
	if err != nil {
		return nil, fmt.Errorf("query kev: %w", err)
	}

	// Build KEV ID set
	kevIDs, _ := store.KEVIDs(db.DB())

	// Build report CVEs from store CVEs
	reportCVEs := make([]CVE, 0, len(cves))
	for _, c := range cves {
		inKEV := c.InKEV || kevIDs[c.CVEID]
		hasPoC := c.HasPoC || len(c.Data.ExploitRefs) > 0 || len(c.Data.PoCLinks) > 0
		priority := assignPriority(inKEV, hasPoC, c.Score)
		ecosystem := c.Data.Ecosystem
		if ecosystem == "" {
			ecosystem = deriveEcosystem(c.Data.Product)
		}
		sector := categorize(c.Data.Product, c.Description, c.Data.CWE)
		category := deriveCategory(c.Data.Product, c.Description, c.Data.CWE)
		if c.Category != "" {
			category = c.Category
		}

		reportCVEs = append(reportCVEs, CVE{
			ID:              c.CVEID,
			Title:           c.Data.Title,
			Severity:        c.Severity,
			Score:           c.Score,
			Priority:        priority,
			Ecosystem:       ecosystem,
			Product:         c.Data.Product,
			CWE:             c.Data.CWE,
			CWENames:        c.Data.CWENames,
			Description:     c.Description,
			DescriptionHTML: md2html(c.Description),
			References:      c.Data.References,
			ExploitRefs:     c.Data.ExploitRefs,
			PoCLinks:        c.Data.PoCLinks,
			Source:          c.Provider,
			InKEV:           inKEV,
			HasPoC:          hasPoC,
			Published:       c.Published,
			CVSSVector:      c.Data.CVSSVector,
			VulnRange:       c.Data.VulnRange,
			PatchedVer:      c.Data.PatchedVer,
			EPSSPct:         c.Data.EPSSPct,
			EPSSPctile:      c.Data.EPSSPctile,
			GHSAURL:         c.Data.GHSAURL,
			NVDURL:          c.Data.NVDURL,
			Category:        category,
		})
		// Stash sector for grouping
		_ = sector
	}

	// Assign sectors
	for i := range reportCVEs {
		c := &cves[i]
		sector := categorize(c.Data.Product, c.Description, c.Data.CWE)
		// Use the sector name as the Category for sector grouping
		reportCVEs[i].Category = reportCVEs[i].Category
		// We'll use a separate field for sector — reusing Category is messy
		// Instead, let's add sector to the grouping logic directly
		_ = sector
	}

	// Group by sector
	sectorMap := make(map[string][]CVE)
	for _, rc := range reportCVEs {
		sector := categorize(rc.Product, rc.Description, rc.CWE)
		sectorMap[sector] = append(sectorMap[sector], rc)
	}

	// Build sector list sorted by P1 count then total
	sectors := make([]Sector, 0, len(sectorMap))
	for name, secCVEs := range sectorMap {
		p1 := 0
		kevCount := 0
		pocCount := 0
		for _, c := range secCVEs {
			if c.Priority == "P1" {
				p1++
			}
			if c.InKEV {
				kevCount++
			}
			if c.HasPoC {
				pocCount++
			}
		}
		sectors = append(sectors, Sector{
			Name:     name,
			Icon:     sectorIcons[name],
			Count:    len(secCVEs),
			P1Count:  p1,
			KEVCount: kevCount,
			PoCCount: pocCount,
			CVEs:     secCVEs,
		})
	}
	sort.Slice(sectors, func(i, j int) bool {
		if sectors[i].P1Count != sectors[j].P1Count {
			return sectors[i].P1Count > sectors[j].P1Count
		}
		return sectors[i].Count > sectors[j].Count
	})

	// Build KEV recent list
	kevRecent := make([]KEV, 0, len(kevEntries))
	for _, e := range kevEntries {
		// Cross-ref with CVE data
		var cveData *store.CVE
		if cv, err := store.GetCVE(db.DB(), e.CVEID); err == nil && cv != nil {
			cveData = cv
		}

		var score float64
		var severity string
		var cwe []string
		var exploitRefs, pocLinks, refs []string
		var product, ecosystem, title, desc, nvdURL, cvssVector, vulnRange, patchedVer, ghsaURL, category string
		var epssPct, epssPctile float64
		var hasPoC bool

		if cveData != nil {
			score = cveData.Score
			severity = cveData.Severity
			cwe = cveData.Data.CWE
			exploitRefs = cveData.Data.ExploitRefs
			pocLinks = cveData.Data.PoCLinks
			refs = cveData.Data.References
			product = cveData.Data.Product
			ecosystem = deriveEcosystem(product)
			desc = cveData.Description
			nvdURL = cveData.Data.NVDURL
			cvssVector = cveData.Data.CVSSVector
			vulnRange = cveData.Data.VulnRange
			patchedVer = cveData.Data.PatchedVer
			ghsaURL = cveData.Data.GHSAURL
			epssPct = cveData.Data.EPSSPct
			epssPctile = cveData.Data.EPSSPctile
			hasPoC = len(exploitRefs) > 0 || len(pocLinks) > 0
			category = deriveCategory(product, desc, cwe)
		}
		if nvdURL == "" && strings.HasPrefix(e.CVEID, "CVE-") {
			nvdURL = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", e.CVEID)
		}
		if title == "" {
			title = deriveTitle(desc, e.VulnName)
		}

		kevRecent = append(kevRecent, KEV{
			CVEID:           e.CVEID,
			VendorProduct:   e.VendorProduct,
			VulnName:        e.VulnName,
			DateAdded:       e.DateAdded,
			DueDate:         e.DueDate,
			DaysLeft:        e.DaysLeft,
			RequiredAction:  e.RequiredAction,
			Score:           score,
			Severity:        severity,
			CWE:             cwe,
			ExploitRefs:     exploitRefs,
			PoCLinks:        pocLinks,
			References:      refs,
			Product:         product,
			Ecosystem:       ecosystem,
			Title:           title,
			Description:     desc,
			DescriptionHTML: md2html(desc),
			NVDURL:          nvdURL,
			HasPoC:          hasPoC,
			CVSSVector:      cvssVector,
			VulnRange:       vulnRange,
			PatchedVer:      patchedVer,
			EPSSPct:         epssPct,
			EPSSPctile:      epssPctile,
			GHSAURL:         ghsaURL,
			Category:        category,
		})
	}
	sort.Slice(kevRecent, func(i, j int) bool {
		return kevRecent[i].DateAdded > kevRecent[j].DateAdded
	})

	// Build meta
	p1, p2, p3 := 0, 0, 0
	for _, c := range reportCVEs {
		switch c.Priority {
		case "P1":
			p1++
		case "P2":
			p2++
		case "P3":
			p3++
		}
	}

	sourceParts := []string{}
	healths, _ := store.GetAllSourceHealth(db.DB())
	for _, h := range healths {
		if h.EntryCount > 0 {
			sourceParts = append(sourceParts, fmt.Sprintf("%s %d", h.SourceName, h.EntryCount))
		}
	}

	report := &CTIReport{
		Meta: Meta{
			GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 MST"),
			WindowHours: hours,
			TotalUnique: len(reportCVEs),
			P1:          p1,
			P2:          p2,
			P3:          p3,
			Sources:     strings.Join(sourceParts, " + "),
		},
		KEVRecent: kevRecent,
		Sectors:   sectors,
	}

	return report, nil
}

// GenerateHTML builds and renders the full HTML report.
func GenerateHTML(db *store.Store, hours int) (string, error) {
	report, err := BuildReport(db, hours)
	if err != nil {
		return "", err
	}
	return Render(report)
}
