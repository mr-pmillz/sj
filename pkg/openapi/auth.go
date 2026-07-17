package openapi

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
)

func CheckSecuritySchemes(spec map[string]interface{}, cfg *config.Config, in io.Reader) {
	components, ok := spec["components"].(map[string]interface{})
	if !ok || components == nil {
		return
	}
	securitySchemes, ok := components["securitySchemes"].(map[string]interface{})
	if !ok || len(securitySchemes) == 0 {
		fmt.Println("No security schemes defined.")
		return
	}

	if cfg.OutputFormat != "json" {
		fmt.Println("Found security schemes:")
	}

	for mechanism, value := range securitySchemes {
		fmt.Printf("  - %s\n", mechanism)
		scheme, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		typ, ok := scheme["type"].(string)
		if !ok {
			continue
		}

		switch typ {
		case "http":
			schemeType, _ := scheme["scheme"].(string)
			switch schemeType {
			case "basic":
				if cfg.Quiet {
					output.PrintWarn("A basic authentication header is accepted. Review the spec and craft a header manually using the -H flag.")
				} else {
					fmt.Println("Basic Authentication is accepted. Supply a username and password? (y/N)")
					var answer string
					fmt.Fscanln(in, &answer)
					if strings.ToLower(answer) == "y" {
						var user, pass string
						fmt.Printf("Enter a username.")
						fmt.Fscanln(in, &user)
						fmt.Printf("Enter a password.")
						fmt.Fscanln(in, &pass)
						encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
						output.PrintInfo("Using %s as the Basic Auth value.\n", encoded)
						cfg.Headers = append(cfg.Headers, "Authorization: Basic "+encoded)
					} else {
						output.PrintWarn("A basic authentication header is accepted. Review the spec and craft a header manually using the -H flag.")
					}
				}
			case "bearer":
				output.PrintWarn("A bearer token is accepted. Review the spec and craft a token manually using the -H flag.")
			}

		case "apiKey":
			inVal, _ := scheme["in"].(string)
			nameVal, _ := scheme["name"].(string)
			switch inVal {
			case "query":
				output.PrintInfo("An API key can be provided via a parameter string. Would you like to apply one? (y/N)\n")
				if !cfg.Quiet {
					var answer string
					fmt.Fscanln(in, &answer)
					if strings.ToLower(answer) == "y" {
						var apiKey string
						fmt.Printf("What value would you like to use for the API key (%s)?", nameVal)
						fmt.Fscanln(in, &apiKey)
						output.PrintInfo("Using %s=%s as the API key in all requests.\n", nameVal, apiKey)
					}
				}
			case "header":
				if mechanism == "bearer" {
					output.PrintInfo("A bearer token is accepted. Would you like to provide one? (y/N)\n")
					if !cfg.Quiet {
						var answer string
						fmt.Fscanln(in, &answer)
						if strings.ToLower(answer) == "y" {
							var token string
							fmt.Printf("What value would you like to use for the Bearer Token? ")
							fmt.Fscanln(in, &token)
							cfg.Headers = append(cfg.Headers, "Authorization: Bearer "+token)
						} else {
							output.PrintWarn("A bearer token is accepted. Review the spec and craft a header manually using the -H flag.")
						}
					}
				} else if nameVal != "" {
					output.PrintInfo("An API key can be provided via the header %s. Would you like to apply one? (y/N)\n", nameVal)
					if !cfg.Quiet {
						var answer string
						fmt.Fscanln(in, &answer)
						if strings.ToLower(answer) == "y" {
							var apiKey string
							fmt.Printf("What value would you like to use for the API key (%s)?", nameVal)
							fmt.Fscanln(in, &apiKey)
							cfg.Headers = append(cfg.Headers, nameVal+": "+apiKey)
						}
					}
				}
			}
		}

		if bearerFormat, ok := scheme["bearerFormat"].(string); ok {
			fmt.Println("  - bearerFormat:", bearerFormat)
		}
	}
}
