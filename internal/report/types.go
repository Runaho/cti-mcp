package report

// CTIReport is the top-level structure for the HTML report template.
type CTIReport struct {
	Meta      Meta    `json:"meta"`
	KEVRecent []KEV   `json:"kev_recent"`
	Sectors   []Sector `json:"sectors"`
}

type Meta struct {
	GeneratedAt string `json:"generated_at"`
	WindowHours int    `json:"window_hours"`
	TotalUnique int    `json:"total_unique"`
	P1          int    `json:"p1"`
	P2          int    `json:"p2"`
	P3          int    `json:"p3"`
	Sources     string `json:"sources"`
	NVDOk       int    `json:"nvd_ok"`
}

type KEV struct {
	CVEID          string   `json:"cve_id"`
	VendorProduct  string   `json:"vendor_product"`
	VulnName       string   `json:"vuln_name"`
	DateAdded      string   `json:"date_added"`
	DueDate        string   `json:"due_date"`
	DaysLeft       int      `json:"days_left"`
	RequiredAction string   `json:"required_action"`
	Score          float64  `json:"score"`
	Severity       string   `json:"severity"`
	CWE            []string `json:"cwe"`
	CWENames       []string `json:"cwe_names"`
	ExploitRefs    []string `json:"exploit_refs"`
	PoCLinks       []string `json:"poc_links"`
	References     []string `json:"references"`
	Product        string   `json:"product"`
	Ecosystem      string   `json:"ecosystem"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	DescriptionHTML string `json:"description_html"`
	NVDURL         string   `json:"nvd_url"`
	HasPoC         bool     `json:"has_poc"`
	CVSSVector     string   `json:"cvss_vector"`
	VulnRange      string   `json:"vuln_range"`
	PatchedVer     string   `json:"patched_ver"`
	EPSSPct        float64  `json:"epss_pct"`
	EPSSPctile     float64  `json:"epss_percentile"`
	GHSAURL        string   `json:"ghsa_url"`
	Category       string   `json:"category"`
}

type Sector struct {
	Name     string `json:"name"`
	Icon     string `json:"icon"`
	Count    int    `json:"count"`
	P1Count  int    `json:"p1_count"`
	KEVCount int    `json:"kev_count"`
	PoCCount int    `json:"poc_count"`
	CVEs     []CVE  `json:"cves"`
}

type CVE struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	Score           float64  `json:"score"`
	Priority        string   `json:"priority"`
	Ecosystem       string   `json:"ecosystem"`
	Product         string   `json:"product"`
	CWE             []string `json:"cwe"`
	CWENames        []string `json:"cwe_names"`
	Description     string   `json:"description"`
	DescriptionHTML string   `json:"description_html"`
	References      []string `json:"references"`
	ExploitRefs     []string `json:"exploit_refs"`
	PoCLinks        []string `json:"poc_links"`
	Source          string   `json:"source"`
	InKEV           bool     `json:"in_kev"`
	HasPoC          bool     `json:"has_poc"`
	Published       string   `json:"published"`
	CVSSVector      string   `json:"cvss_vector"`
	VulnRange       string   `json:"vuln_range"`
	PatchedVer      string   `json:"patched_ver"`
	EPSSPct         float64  `json:"epss_pct"`
	EPSSPctile      float64  `json:"epss_percentile"`
	GHSAURL         string   `json:"ghsa_url"`
	NVDURL          string   `json:"nvd_url"`
	Category        string   `json:"category"`
}
