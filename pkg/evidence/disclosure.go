package evidence

import (
	"regexp"
	"slices"
	"strings"
)

// disclosurePatterns recognize backend diagnostics in a response body. A
// medium entry reveals a stack trace or database detail on its own. A low
// entry is a framework or runtime diagnostic. A supporting entry counts
// only next to stronger evidence.
var disclosurePatterns = []struct {
	name    string
	tier    string
	pattern *regexp.Regexp
}{
	{name: "stack_trace", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:stack trace|traceback|unhandled exception|"backtrace"\s*:\s*\[[\s\S]{0,1000}"(?:file|filename)"\s*:[\s\S]{0,1000}"line(?:_number)?"\s*:\s*\d+)`)},
	{name: "runtime_diagnostic", tier: "low", pattern: regexp.MustCompile(`(?i)(?:json:\s*cannot unmarshal|strconv\.parse(?:int|float)|\.go:\d+|\.java:\d+|(?:\bfile\b|\bat\b|stack|traceback)[^\r\n]{0,80}(?:/home/|C:\\Users\\)[^\r\n"']+)`)},
	{name: "pydantic_validation", tier: "low", pattern: regexp.MustCompile(`(?i)(?:errors\.pydantic\.dev|validation errors? for [a-z_][a-z0-9_]*schema|input_type=|\[type=missing)`)},
	{name: "upstream_client", tier: "low", pattern: regexp.MustCompile(`(?i)(?:httpsconnectionpool|nameresolutionerror|urllib3\.connection|name or service not known)`)},
	{name: "database_error", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:sqlstate|ORA-\d+|syntax error at or near|cannot insert the value null|sqlparamdata)`)},
	{name: "database_driver", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:pyodbc(?:\.[a-z]+)?|\[ODBC Driver[^\]]*\]|\[Microsoft\]\[ODBC Driver[^\]]*\])`)},
	{name: "database_framework", tier: "medium", pattern: regexp.MustCompile(`(?i)(?:sqlalchemy(?:\.[a-z]+)?|sqlalche\.me\/e\/)`)},
	{name: "database_server", tier: "supporting", pattern: regexp.MustCompile(`(?i)(?:\[SQL Server\]|Microsoft SQL Server)`)},
	{name: "database_table", tier: "supporting", pattern: regexp.MustCompile(`(?i)\btable\s+['\"\[]?[a-z0-9_$-]+(?:\.[a-z0-9_$-]+){1,3}`)},
	{name: "database_column", tier: "supporting", pattern: regexp.MustCompile(`(?i)\bcolumn\s+['\"\[]?[a-z_][a-z0-9_$-]*`)},
	{name: "database_constraint", tier: "supporting", pattern: regexp.MustCompile(`(?i)\bconstraint\s+['\"\[]?[a-z_][a-z0-9_$-]*`)},
	{name: "stored_procedure", tier: "supporting", pattern: regexp.MustCompile(`(?i)\bEXEC(?:UTE)?\s+[a-z_][a-z0-9_.]*\s+@`)},
	{name: "sql_statement", tier: "medium", pattern: regexp.MustCompile(`(?i)\[SQL:\s`)},
	{name: "sql_parameters", tier: "medium", pattern: regexp.MustCompile(`(?i)\[(?:parameters?|params):\s`)},
}

// DisclosureTypes names the backend diagnostics a response body contains.
func DisclosureTypes(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	types := make([]string, 0, len(disclosurePatterns))
	for _, candidate := range disclosurePatterns {
		if candidate.pattern.Match(body) {
			types = append(types, candidate.name)
		}
	}
	return types
}

// DisclosureTiers splits disclosure type names by severity. Supporting
// types are promoted to medium next to another medium type, or when an
// error response names a database object.
func DisclosureTiers(types []string, status int) (medium, low []string) {
	unique := make([]string, 0, len(types))
	for _, disclosureType := range types {
		if disclosureType = strings.TrimSpace(disclosureType); disclosureType != "" {
			unique = append(unique, disclosureType)
		}
	}
	slices.Sort(unique)
	unique = slices.Compact(unique)
	supporting := make([]string, 0)
	for _, disclosureType := range unique {
		tier := "supporting"
		for _, candidate := range disclosurePatterns {
			if candidate.name == disclosureType {
				tier = candidate.tier
				break
			}
		}
		switch tier {
		case "medium":
			medium = append(medium, disclosureType)
		case "low":
			low = append(low, disclosureType)
		default:
			supporting = append(supporting, disclosureType)
		}
	}
	if len(medium) > 0 || status >= 400 && namesDatabaseObject(supporting) {
		medium = append(medium, supporting...)
	}
	return medium, low
}

func namesDatabaseObject(types []string) bool {
	for _, disclosureType := range types {
		switch disclosureType {
		case "database_table", "database_column", "database_constraint", "stored_procedure":
			return true
		}
	}
	return false
}
