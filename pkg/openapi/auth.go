package openapi

import (
	"sort"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
)

func CheckSecuritySchemes(spec map[string]any, cfg *config.Config) {
	schemes := securitySchemes(spec)
	if len(schemes) == 0 {
		output.PrintWarn("No security schemes are defined in the specification.")
		return
	}
	names := make([]string, 0, len(schemes))
	for name := range schemes {
		names = append(names, name)
	}
	sort.Strings(names)
	safeNames := make([]string, 0, len(names))
	for _, name := range names {
		safeNames = append(safeNames, output.TerminalSafe(name))
	}
	output.PrintInfo("Security schemes declared: %s\n", strings.Join(safeNames, ", "))
	for _, name := range names {
		scheme, ok := schemes[name].(map[string]any)
		if !ok {
			continue
		}
		typeName, _ := scheme["type"].(string)
		switch typeName {
		case "basic":
			output.PrintWarn("%s uses HTTP Basic authentication; supply credentials explicitly with --headers if authorized.", output.TerminalSafe(name))
		case "http":
			httpScheme, _ := scheme["scheme"].(string)
			output.PrintInfo("Security scheme %s uses HTTP %s authentication; credentials are never prompted for or logged.\n", output.TerminalSafe(name), output.TerminalSafe(httpScheme))
		case "apiKey":
			location, _ := scheme["in"].(string)
			parameter, _ := scheme["name"].(string)
			output.PrintInfo("Security scheme %s expects API key %s in %s; provide it explicitly if authorized.\n", output.TerminalSafe(name), output.TerminalSafe(parameter), output.TerminalSafe(location))
		case "oauth2", "openIdConnect", "mutualTLS":
			output.PrintInfo("Security scheme %s uses %s; configure authorized credentials externally.\n", output.TerminalSafe(name), output.TerminalSafe(typeName))
		default:
			output.PrintInfo("Security scheme %s has type %q.\n", output.TerminalSafe(name), output.TerminalSafe(typeName))
		}
	}
	_ = cfg // retained for API symmetry and future output policy.
}

func securitySchemes(spec map[string]any) map[string]any {
	if components, ok := spec["components"].(map[string]any); ok {
		if schemes, ok := components["securitySchemes"].(map[string]any); ok {
			return schemes
		}
	}
	schemes, _ := spec["securityDefinitions"].(map[string]any)
	return schemes
}
