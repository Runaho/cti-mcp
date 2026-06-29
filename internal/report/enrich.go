package report

import (
	"bytes"
	"embed"
	"fmt"
	"html"
	"html/template"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed template.html
var templateFS embed.FS

var (
	codeBlockRe = regexp.MustCompile("(?s)```(\\w*)\n(.*?)```")
	inlineCodeRe = regexp.MustCompile("`([^`]+)`")
	boldRe       = regexp.MustCompile(`\*\*(.+?)\*\*`)
	h3Re         = regexp.MustCompile(`(?m)^### (.+)$`)
	h4Re         = regexp.MustCompile(`(?m)^## (.+)$`)
	ulRe         = regexp.MustCompile(`(?m)^- (.+)$`)
	olRe         = regexp.MustCompile(`(?m)^\d+\. (.+)$`)
	urlRe        = regexp.MustCompile(`(https?://[^\s<]+)`)
)

func md2html(text string) string {
	if text == "" {
		return ""
	}
	// Escape ALL HTML entities first — prevents XSS from CVE descriptions
	// that may contain <script>, <img onerror>, or other injected HTML.
	// Markdown syntax (*, `, #, -, https://) is not affected by HTML escaping.
	text = html.EscapeString(text)
	// Note: input is already HTML-escaped above, so no need to escape
	// again inside code blocks — that would cause double-escaping.
	text = codeBlockRe.ReplaceAllStringFunc(text, func(m string) string {
		subs := codeBlockRe.FindStringSubmatch(m)
		if len(subs) >= 3 {
			return "<pre><code>" + subs[2] + "</code></pre>"
		}
		return m
	})
	text = inlineCodeRe.ReplaceAllStringFunc(text, func(m string) string {
		subs := inlineCodeRe.FindStringSubmatch(m)
		if len(subs) >= 2 {
			return "<code>" + subs[1] + "</code>"
		}
		return m
	})
	text = boldRe.ReplaceAllString(text, "<strong>$1</strong>")
	text = h3Re.ReplaceAllString(text, "<h4>$1</h4>")
	text = h4Re.ReplaceAllString(text, "<h3>$1</h3>")
	text = ulRe.ReplaceAllString(text, "<li>$1</li>")
	text = olRe.ReplaceAllString(text, "<li>$1</li>")
	text = urlRe.ReplaceAllString(text, `<a href="$1" target="_blank">$1</a>`)

	parts := strings.Split(text, "\n\n")
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "<pre") || strings.HasPrefix(part, "<h3") ||
			strings.HasPrefix(part, "<h4") || strings.HasPrefix(part, "<ul") ||
			strings.HasPrefix(part, "<li") {
			result = append(result, part)
		} else {
			part = strings.ReplaceAll(part, "\n", "<br>")
			result = append(result, "<p>"+part+"</p>")
		}
	}
	return strings.Join(result, "\n")
}

func deriveTitle(desc, vulnName string) string {
	if vulnName != "" {
		if len(vulnName) > 200 {
			return vulnName[:197] + "..."
		}
		return vulnName
	}
	if desc == "" {
		return ""
	}
	firstLine := strings.SplitN(desc, "\n", 2)[0]
	if len(firstLine) > 200 {
		return firstLine[:197] + "..."
	}
	return firstLine
}

func deriveEcosystem(product string) string {
	p := strings.ToLower(product)
	if strings.HasPrefix(p, "npm/") {
		return "npm"
	}
	if strings.HasPrefix(p, "pip/") {
		return "pip"
	}
	if strings.HasPrefix(p, "go/") {
		return "go"
	}
	if strings.HasPrefix(p, "composer/") {
		return "composer"
	}
	if strings.HasPrefix(p, "maven/") {
		return "maven"
	}
	if strings.HasPrefix(p, "gem/") {
		return "gem"
	}
	if strings.HasPrefix(p, "cargo/") {
		return "cargo"
	}
	if strings.HasPrefix(p, "nuget/") {
		return "nuget"
	}
	return "unknown"
}

var sectorKeywords = map[string][]string{
	"Container / Cloud-Native": {"kubernetes", "docker", "container", "runc", "podman", "cri-o"},
	"Cloud Infrastructure":     {"aws", "azure", "gcp", "terraform", "eks", "aks"},
	"Web Servers & Proxies":    {"nginx", "apache", "caddy", "traefik", "haproxy", "iis"},
	"Operating System":         {"linux", "kernel", "windows", "macos", "freebsd", "openssh", "systemd"},
	"Dev Tools & IDEs":         {"jupyter", "vscode", "intellij", "ide", "editor"},
	"Browsers":                 {"chrome", "firefox", "safari", "webkit", "browser", "electron"},
	"Databases":                {"postgres", "mysql", "mariadb", "mongodb", "redis", "sqlite", "mssql"},
	"Cryptography & TLS":       {"openssl", "libssl", "gnutls", "tls", "cert", "crypto"},
	"Web Frameworks":           {"django", "flask", "fastapi", "express", "rails", "spring", "laravel", "gin", "fiber"},
	"Package Registries":       {"npm/", "pip/", "gem/", "composer/", "cargo/", "maven/", "nuget/", "pypi"},
	"Frontend Frameworks":      {"react", "vue", "angular", "next", "nuxt", "svelte"},
	"Network & Firewall":       {"router", "switch", "cisco", "fortinet", "paloalto", "juniper", "firewall"},
	"Enterprise Software":      {"splunk", "cpanel", "joomla", "wordpress", "drupal", "confluence", "jira"},
	"RCE / Code Execution":     {"rce", "remote code execution", "arbitrary code", "command injection", "deserialization"},
	"Web Vulnerabilities":      {"xss", "cross-site scripting", "csrf", "clickjacking"},
	"Access Control":           {"ssrf", "server-side request", "broken access"},
	"Privilege Escalation":     {"privilege escalation", "privesc", "root", "admin"},
	"Injection":                {"sql injection", "sqli"},
	"File Access / Traversal":  {"file read", "path traversal", "directory traversal", "arbitrary file"},
	"Other":                    {},
}

var sectorIcons = map[string]string{
	"Container / Cloud-Native": "container",
	"Cloud Infrastructure":     "cloud",
	"Web Servers & Proxies":    "server",
	"Operating System":         "os",
	"Dev Tools & IDEs":         "tools",
	"Browsers":                 "browser",
	"Databases":                "db",
	"Cryptography & TLS":       "crypto",
	"Web Frameworks":           "framework",
	"Package Registries":       "package",
	"Frontend Frameworks":      "frontend",
	"Network & Firewall":       "network",
	"Enterprise Software":      "enterprise",
	"RCE / Code Execution":     "rce",
	"Web Vulnerabilities":      "web",
	"Access Control":           "access",
	"Privilege Escalation":     "privesc",
	"Injection":                "injection",
	"File Access / Traversal":  "file",
	"Other":                    "other",
}

func categorize(product, desc string, cwe []string) string {
	p := strings.ToLower(product)
	d := strings.ToLower(desc)
	cwes := strings.ToLower(strings.Join(cwe, " "))
	combined := p + " " + d

	for sector, keywords := range sectorKeywords {
		if sector == "Other" {
			continue
		}
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				return sector
			}
		}
	}
	if strings.Contains(cwes, "cwe-78") || strings.Contains(cwes, "cwe-94") || strings.Contains(cwes, "cwe-77") {
		return "Injection"
	}
	if strings.Contains(cwes, "cwe-79") || strings.Contains(cwes, "cwe-89") {
		return "Web Vulnerabilities"
	}
	if strings.Contains(cwes, "cwe-22") || strings.Contains(cwes, "cwe-787") || strings.Contains(cwes, "cwe-125") {
		return "Operating System"
	}
	return "Other"
}

func deriveCategory(product, desc string, cwe []string) string {
	// Simplified category — reuses categorize with different buckets
	p := strings.ToLower(product)
	d := strings.ToLower(desc)
	cwes := strings.ToLower(strings.Join(cwe, " "))
	combined := p + " " + d

	categoryMap := map[string][]string{
		"Web":            {"web", "http", "html", "javascript", "react", "vue", "angular", "xss", "csrf"},
		"Cloud":          {"aws", "azure", "kubernetes", "docker", "container", "terraform"},
		"AI/ML":          {"ai", "ml", "llm", "gpt", "langchain", "transformers", "pytorch"},
		"Server/Infra":   {"nginx", "apache", "linux", "kernel", "postgres", "mysql", "redis"},
		"Network":        {"router", "cisco", "firewall", "vpn", "dns", "rce"},
		"Dev/Tools":      {"npm", "pip", "gem", "cargo", "maven", "compiler", "build"},
		"Security/Crypto": {"openssl", "tls", "crypto", "jwt", "auth", "oauth"},
		"Enterprise":     {"splunk", "wordpress", "drupal", "jira", "sap", "oracle"},
		"IoT/Embedded":   {"iot", "firmware", "hardware", "scada"},
	}

	scores := make(map[string]int)
	for cat, keywords := range categoryMap {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				scores[cat]++
			}
		}
	}

	if len(scores) > 0 {
		best := ""
		max := 0
		for cat, score := range scores {
			if score > max {
				max = score
				best = cat
			}
		}
		return best
	}

	if strings.Contains(cwes, "cwe-78") || strings.Contains(cwes, "cwe-94") {
		return "Network"
	}
	if strings.Contains(cwes, "cwe-79") {
		return "Web"
	}
	return "Other"
}

func assignPriority(inKEV, hasPoC bool, score float64) string {
	if inKEV || hasPoC {
		return "P1"
	}
	if score >= 9.0 {
		return "P2"
	}
	return "P3"
}

// RenderHTML generates the HTML report from a CTIReport struct.
func RenderHTML(r *CTIReport) (string, error) {
	funcMap := template.FuncMap{
		"upper":      strings.ToUpper,
		"lower":      strings.ToLower,
		"trimPrefix": strings.TrimPrefix,
		"split":      strings.Split,
		"join":       strings.Join,
		"contains":   strings.Contains,
		"hasPrefix":  strings.HasPrefix,
		"formatDate": formatDate,
		"daysUntil":  daysUntil,
		"now":        time.Now,
		"safeHTML":   func(s string) template.HTML { return template.HTML(s) },
		"safeURL":    func(s string) template.URL { return template.URL(s) },
		"dict":       dict,
		"truncate":   truncateStr,
		"mul":        func(a, b float64) float64 { return a * b },
	}

	tmplBytes, err := templateFS.ReadFile("template.html")
	if err != nil {
		return "", fmt.Errorf("read embedded template: %w", err)
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(tmplBytes))
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	_ = filepath.Base // unused but needed for potential template path changes

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

func formatDate(s string) string {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Format("02 Jan 2006")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("02 Jan 2006 15:04 MST")
	}
	return s
}

func daysUntil(dateStr string) int {
	if t, err := time.Parse("2006-01-02", dateStr); err == nil {
		return int(t.Sub(time.Now()).Hours() / 24)
	}
	return 0
}

func dict(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("dict: odd number of arguments")
	}
	m := make(map[string]any)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict: key %d is not a string", i)
		}
		m[key] = values[i+1]
	}
	return m, nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Ensure sort import is used
var _ = sort.Strings
