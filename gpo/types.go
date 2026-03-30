package gpo

import (
	"encoding/xml"
	"time"
)

// The top-level structure returned to the web UI
type Report struct {
	GeneratedAt  time.Time
	ComputerName string
	UserName     string
	DomainName   string
	SiteName     string
	Computer     *ResultSet
	User         *ResultSet
	FetchError   error
}

// Holds the applied GPOs and policy settings for one scope (computer
// or user).
type ResultSet struct {
	Scope          string // "Computer" or "User"
	Domain         string
	Site           string
	SlowLink       bool
	GPOs           []AppliedGPO
	SecurityGroups []SecurityGroup
	SOMs           []SOM
	Extensions     []Extension
}

// Describes one GPO that was evaluated for the scope.
type AppliedGPO struct {
	Name            string
	GUID            string
	Domain          string
	Enabled         bool
	FilterAllowed   bool
	AccessDenied    bool
	IsValid         bool
	UserVersion     int
	ComputerVersion int
	SOMOrder        int
	AppliedOrder    int
	Link            string
	SysvolPath      string
}

// Scope of Management container (eg. site, domain, OU).
type SOM struct {
	Path               string
	Type               string
	Blocked            bool
	BlockedInheritance bool
	InheritanceBlocked bool
	GPOsApplied        int
	GPOsInaccessible   int
}

// Security group the computer/user belongs to.
type SecurityGroup struct {
	SID            string
	SamAccountName string
	IsMember       bool
}

// Settings applied by one CSE
type Extension struct {
	Name     string
	Policies []Policy // ADMX / Registry policies
	Scripts  []Script // Startup / Shutdown / Logon / Logoff scripts
	Items    []KeyVal // Generic key/value settings (Security etc.)
	RawXML   string   // unknown extensions
}

// A single ADMX policy setting.
type Policy struct {
	Name     string
	State    string // Enabled | Disabled | Not Configured
	Category string
	Explain  string
	GPO      string
	Settings []KeyVal
}

// A startup/shutdown/logon/logoff script entry.
type Script struct {
	ScriptType string // Startup | Shutdown | Logon | Logoff
	Order      int
	Command    string
	Args       string
	GPO        string
}

// Generic name/value pair used for settings that don't have a
// more specific representation.
type KeyVal struct {
	Name  string
	Value string
}

// Raw XML models

type xmlRSoP struct {
	XMLName         xml.Name   `xml:"Rsop"`
	ComputerResults xmlResults `xml:"ComputerResults"`
	UserResults     xmlResults `xml:"UserResults"`
}

type xmlResults struct {
	SearchedSOM    xmlSearchedSOM     `xml:"SearchedSOM"`
	EventSource    xmlEventSource     `xml:"EventSource"`
	SecurityGroups xmlSecurityGroups  `xml:"SecurityGroups"`
	ExtensionData  []xmlExtensionData `xml:"ExtensionData"`
}

type xmlSearchedSOM struct {
	SOMs []xmlSOM `xml:"SOM"`
}

type xmlSOM struct {
	Path               string `xml:"Path"`
	Type               string `xml:"Type"`
	Blocked            bool   `xml:"Blocked"`
	BlockedInheritance bool   `xml:"BlockedInheritance"`
	InheritanceBlocked bool   `xml:"InheritanceBlocked"`
	GPOsApplied        int    `xml:"GPOsApplied"`
	GPOsInaccessible   int    `xml:"GPOsInaccessible"`
}

type xmlEventSource struct {
	Domain   string   `xml:"Domain"`
	Site     string   `xml:"Site"`
	SlowLink bool     `xml:"SlowLink"`
	GPOs     []xmlGPO `xml:"GPO"`
}

type xmlGPO struct {
	Name          string        `xml:"Name"`
	Identifier    xmlIdentifier `xml:"Identifier"`
	Version       xmlVersion    `xml:"Version"`
	FilterAllowed bool          `xml:"FilterAllowed"`
	AccessDenied  bool          `xml:"AccessDenied"`
	Enabled       bool          `xml:"Enabled"`
	IsValid       bool          `xml:"IsValid"`
	SOMOrder      int           `xml:"SOMOrder"`
	AppliedOrder  int           `xml:"AppliedOrder"`
	Link          string        `xml:"Link"`
	SysvolPath    string        `xml:"SysvolPath"`
}

type xmlIdentifier struct {
	GUID   string `xml:"Identifier"`
	Domain string `xml:"Domain"`
}

type xmlVersion struct {
	UserVersion     int `xml:"UserVersion"`
	ComputerVersion int `xml:"ComputerVersion"`
}

type xmlSecurityGroups struct {
	Groups []xmlSecurityGroup `xml:"Group"`
}

type xmlSecurityGroup struct {
	Name     xmlGroupName `xml:"Name"`
	IsMember bool         `xml:"IsMember"`
}

type xmlGroupName struct {
	SID            string `xml:"Sid"`
	SamAccountName string `xml:"SamAccountName"`
}

// xmlExtensionData wrap one CSE block. The inner Extension element is kept
// as raw XML (innerxml) so we can re-parse it with a token scanner that
// ignores namespace prefixes.
type xmlExtensionData struct {
	Name      string `xml:"Name"`
	Extension struct {
		InnerXML string `xml:",innerxml"`
		TypeAttr string `xml:"type,attr"`
	} `xml:"Extension"`
}
