package web

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"gpoview/gpo"
)

//go:embed index.html
var indexHTML string

type templateData struct {
	*gpo.Report
	GeneratedAtFmt string
	HasError       bool
	ErrorMsg       string
}

func StartServer(addr string, report *gpo.Report) error {
	tmpl, err := template.New("index").Funcs(tmplFuncs()).Parse(indexHTML)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := templateData{
			Report:         report,
			GeneratedAtFmt: report.GeneratedAt.Format("Mon, 02 Jan 2006  15:04:05"),
		}
		if report.FetchError != nil {
			data.HasError = true
			data.ErrorMsg = report.FetchError.Error()
		}

		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	return http.ListenAndServe(addr, mux)
}

func tmplFuncs() template.FuncMap {
	return template.FuncMap{
		"lower": strings.ToLower,
		"stateClass": func(s string) string {
			switch strings.ToLower(s) {
			case "enabled":
				return "enabled"
			case "disabled":
				return "disabled"
			default:
				return "unknown"
			}
		},
		"fmtTime": func(t time.Time) string {
			return t.Format("Mon, 02 Jan 2006  15:04:05")
		},
		"add": func(a, b int) int { return a + b },
		"extSummary": func(e gpo.Extension) string {
			parts := []string{}
			if n := len(e.Policies); n > 0 {
				parts = append(parts, fmt.Sprintf("%d polic%s", n, pluralSuffix(n, "y", "ies")))
			}
			if n := len(e.Scripts); n > 0 {
				parts = append(parts, fmt.Sprintf("%d script%s", n, pluralSuffix(n, "", "s")))
			}
			if n := len(e.Items); n > 0 {
				parts = append(parts, fmt.Sprintf("%d item%s", n, pluralSuffix(n, "", "s")))
			}
			if len(parts) == 0 {
				return ""
			}
			return strings.Join(parts, ", ")
		},
		"gpoStatus": func(g gpo.AppliedGPO) [2]string {
			switch {
			case g.AccessDenied:
				return [2]string{"Access Denied", "badge-red"}
			case !g.FilterAllowed:
				return [2]string{"Filtered", "badge-yellow"}
			case !g.Enabled:
				return [2]string{"Disabled", "badge-gray"}
			default:
				return [2]string{"Applied", "badge-green"}
			}
		},
	}
}

func pluralSuffix(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
