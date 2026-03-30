package gpo

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

// Parse decodes a UTF-8 RSoP XML document (produced by gpresult /X) into a
// Report.
func Parse(xmlData []byte) (*Report, error) {
	var rsop xmlRSoP
	if err := xml.Unmarshal(xmlData, &rsop); err != nil {
		return nil, fmt.Errorf("xml unmarshal: %w", err)
	}

	report := &Report{
		GeneratedAt: time.Now(),
	}

	report.Computer = buildResultSet("Computer", &rsop.ComputerResults)
	report.User = buildResultSet("User", &rsop.UserResults)

	// Pull top-level identifiers from whichever scope has data.
	if es := rsop.ComputerResults.EventSource; es.Domain != "" {
		report.DomainName = es.Domain
		report.SiteName = es.Site
	} else if es := rsop.UserResults.EventSource; es.Domain != "" {
		report.DomainName = es.Domain
		report.SiteName = es.Site
	}

	// Derive computer / user names from the first GPO links when not present
	// in the XML directly.
	if len(report.Computer.GPOs) > 0 {
		report.ComputerName = extractCN(report.Computer.GPOs[0].Link)
	}

	return report, nil
}

// buildResultSet converts the raw xmlResults into a clean ResultSet.
func buildResultSet(scope string, r *xmlResults) *ResultSet {
	rs := &ResultSet{Scope: scope}
	rs.Domain = r.EventSource.Domain
	rs.Site = r.EventSource.Site
	rs.SlowLink = r.EventSource.SlowLink

	// SOMs
	for _, s := range r.SearchedSOM.SOMs {
		rs.SOMs = append(rs.SOMs, SOM{
			Path:               s.Path,
			Type:               s.Type,
			Blocked:            s.Blocked,
			BlockedInheritance: s.BlockedInheritance,
			InheritanceBlocked: s.InheritanceBlocked,
			GPOsApplied:        s.GPOsApplied,
			GPOsInaccessible:   s.GPOsInaccessible,
		})
	}

	// GPOs
	for _, g := range r.EventSource.GPOs {
		rs.GPOs = append(rs.GPOs, AppliedGPO{
			Name:            g.Name,
			GUID:            g.Identifier.GUID,
			Domain:          g.Identifier.Domain,
			Enabled:         g.Enabled,
			FilterAllowed:   g.FilterAllowed,
			AccessDenied:    g.AccessDenied,
			IsValid:         g.IsValid,
			UserVersion:     g.Version.UserVersion,
			ComputerVersion: g.Version.ComputerVersion,
			SOMOrder:        g.SOMOrder,
			AppliedOrder:    g.AppliedOrder,
			Link:            g.Link,
			SysvolPath:      g.SysvolPath,
		})
	}

	// Security groups
	for _, sg := range r.SecurityGroups.Groups {
		rs.SecurityGroups = append(rs.SecurityGroups, SecurityGroup{
			SID:            sg.Name.SID,
			SamAccountName: sg.Name.SamAccountName,
			IsMember:       sg.IsMember,
		})
	}

	// Extensions
	for _, ed := range r.ExtensionData {
		ext := parseExtension(ed.Name, ed.Extension.InnerXML)
		rs.Extensions = append(rs.Extensions, ext)
	}

	return rs
}

// ─── Extension parsing ────────────────────────────────────────────────────────

// parseExtension uses a namespace-agnostic token scanner to extract policy
// settings from a CSE extension block.
func parseExtension(name, innerXML string) Extension {
	ext := Extension{Name: name}
	if strings.TrimSpace(innerXML) == "" {
		return ext
	}

	// Wrap in a root element to make the fragment valid XML.
	// We forward-declare the common GPO namespaces so prefix-qualified elements
	// are resolved correctly.
	wrapped := `<root ` +
		`xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/Registry" ` +
		`xmlns:q2="http://www.microsoft.com/GroupPolicy/Settings/Scripts" ` +
		`xmlns:q3="http://www.microsoft.com/GroupPolicy/Settings/Security" ` +
		`xmlns:q4="http://www.microsoft.com/GroupPolicy/Types" ` +
		`>` + innerXML + `</root>`

	switch strings.ToLower(name) {
	case "registry":
		ext.Policies = parseRegistryExtension(wrapped)
	case "scripts":
		ext.Scripts = parseScriptsExtension(wrapped)
	default:
		ext.Items = parseGenericExtension(wrapped)
		if len(ext.Items) == 0 {
			ext.RawXML = prettyXML(innerXML)
		}
	}
	return ext
}

// ── Registry / ADMX ──────────────────────────────────────────────────────────

func parseRegistryExtension(wrappedXML string) []Policy {
	dec := xml.NewDecoder(strings.NewReader(wrappedXML))
	var policies []Policy
	var cur *Policy
	var path []string

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			local := t.Name.Local
			path = append(path, local)
			if local == "Policy" {
				cur = &Policy{}
			}
		case xml.EndElement:
			local := t.Name.Local
			if local == "Policy" && cur != nil {
				policies = append(policies, *cur)
				cur = nil
			}
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" || cur == nil || len(path) == 0 {
				continue
			}
			switch path[len(path)-1] {
			case "Name":
				if cur.Name == "" {
					cur.Name = text
				}
			case "State":
				cur.State = text
			case "Category":
				cur.Category = text
			case "Explain":
				cur.Explain = text
			case "GPO":
				cur.GPO = text
			default:
				// Capture any leaf value as a generic setting entry when we're
				// inside a Policy element and at depth ≥ 2 below it.
				if len(path) >= 2 {
					kv := KeyVal{Name: path[len(path)-1], Value: text}
					cur.Settings = append(cur.Settings, kv)
				}
			}
		}
	}
	return policies
}

// ── Scripts ───────────────────────────────────────────────────────────────────

func parseScriptsExtension(wrappedXML string) []Script {
	dec := xml.NewDecoder(strings.NewReader(wrappedXML))
	var scripts []Script
	var cur *Script
	var path []string
	var scriptType string

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			local := t.Name.Local
			path = append(path, local)
			switch local {
			case "Startup":
				scriptType = "Startup"
			case "Shutdown":
				scriptType = "Shutdown"
			case "Logon":
				scriptType = "Logon"
			case "Logoff":
				scriptType = "Logoff"
			case "Script":
				cur = &Script{ScriptType: scriptType}
				// Read Order attribute.
				for _, attr := range t.Attr {
					if attr.Name.Local == "Order" {
						fmt.Sscanf(attr.Value, "%d", &cur.Order)
					}
				}
			}
		case xml.EndElement:
			local := t.Name.Local
			if local == "Script" && cur != nil {
				scripts = append(scripts, *cur)
				cur = nil
			}
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" || cur == nil || len(path) == 0 {
				continue
			}
			switch path[len(path)-1] {
			case "Command":
				cur.Command = text
			case "Parameters":
				cur.Args = text
			case "GPO":
				cur.GPO = text
			}
		}
	}
	return scripts
}

// parseGenericExtension walks the token stream and emits leaf text nodes as
// KeyVal pairs using a dot-joined element path as the key.
func parseGenericExtension(wrappedXML string) []KeyVal {
	dec := xml.NewDecoder(strings.NewReader(wrappedXML))
	var items []KeyVal
	var path []string

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" || len(path) == 0 {
				continue
			}
			// Skip the synthetic root element.
			if len(path) == 1 && path[0] == "root" {
				continue
			}
			key := strings.Join(path[1:], " › ") // skip synthetic root
			items = append(items, KeyVal{Name: key, Value: text})
		}
	}
	return items
}

// prettyXML re-indents an XML fragment.  Returns the original on error.
func prettyXML(src string) string {
	if src == "" {
		return src
	}
	wrapped := "<root>" + src + "</root>"
	dec := xml.NewDecoder(strings.NewReader(wrapped))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return src
		}
		_ = enc.EncodeToken(tok)
	}
	_ = enc.Flush()
	// Remove the synthetic <root> wrapper lines.
	out := buf.String()
	lines := strings.Split(out, "\n")
	if len(lines) >= 2 {
		lines = lines[1 : len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// extractCN tries to parse a Distinguished Name like
// "CN=MYPC$,OU=Computers,DC=corp,DC=example,DC=com" and return the CN value.
func extractCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "cn") {
			return strings.TrimSuffix(kv[1], "$")
		}
	}
	return ""
}
