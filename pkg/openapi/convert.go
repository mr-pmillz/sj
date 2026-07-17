package openapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
	"gopkg.in/yaml.v3"
)

func ConvertSpec(bodyBytes []byte, cfg *config.Config) {
	var doc openapi2.T
	var doc3 openapi3.T

	format := strings.ToLower(cfg.Format)
	if format == "yaml" || format == "yml" || strings.HasSuffix(cfg.SwaggerURL, ".yaml") || strings.HasSuffix(cfg.SwaggerURL, ".yml") {
		_ = yaml.Unmarshal(bodyBytes, &doc)
		_ = yaml.Unmarshal(bodyBytes, &doc3)
	} else {
		_ = json.Unmarshal(bodyBytes, &doc)
		_ = json.Unmarshal(bodyBytes, &doc3)
	}

	if strings.HasPrefix(doc3.OpenAPI, "3") {
		output.PrintWarn("Definition file is already version 3.")
		WriteConvertedFile(bodyBytes, cfg.Outfile)
	} else if strings.HasPrefix(doc.Swagger, "2") {
		newDoc, err := openapi2conv.ToV3(&doc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error converting v2 document to v3: %s\n", err)
		}

		switch format {
		case "json":
			if strings.HasSuffix(cfg.Outfile, "yaml") || strings.HasSuffix(cfg.Outfile, "yml") {
				output.PrintWarn("It looks like you're trying to save the file in YAML format. Supply the '-f yaml' option to do so (default: json).")
			}
			converted, err := json.Marshal(newDoc)
			if err != nil {
				output.Die("Error converting definition file to v3: %v", err)
			}
			if cfg.Outfile == "" {
				endOfJSON := strings.LastIndex(string(converted), "}") + 1
				if endOfJSON > 0 {
					fmt.Println(string(converted)[:endOfJSON])
				} else {
					fmt.Println(string(converted))
				}
			} else {
				WriteConvertedFile(converted, cfg.Outfile)
			}
		case "yaml", "yml":
			converted, err := yaml.Marshal(newDoc)
			if err != nil {
				output.Die("Error converting definition file to v3: %v", err)
			}
			if cfg.Outfile == "" {
				fmt.Println(string(converted))
			} else {
				WriteConvertedFile(converted, cfg.Outfile)
			}
		}
	} else {
		output.Die("Error parsing definition file.")
	}
}

func WriteConvertedFile(data []byte, outfile string) {
	file, err := os.OpenFile(outfile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		output.PrintErr("Error opening file: %s", err)
		return
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		output.PrintErr("Error writing file: %s", err)
	} else {
		f, _ := filepath.Abs(outfile)
		output.PrintInfo("Wrote file to %s\n", f)
	}
}

func UnmarshalSpec(bodyBytes []byte, cfg *config.Config) *openapi3.T {
	var doc openapi2.T
	var doc3 openapi3.T

	format := strings.ToLower(cfg.Format)
	if format == "js" || strings.HasSuffix(cfg.SwaggerURL, ".js") {
		bodyBytes = ExtractSpecFromJS(bodyBytes)
	} else if format == "yaml" || format == "yml" || strings.HasSuffix(cfg.SwaggerURL, ".yaml") || strings.HasSuffix(cfg.SwaggerURL, ".yml") {
		_ = yaml.Unmarshal(bodyBytes, &doc)
		_ = yaml.Unmarshal(bodyBytes, &doc3)
	}

	_ = json.Unmarshal(bodyBytes, &doc)
	_ = json.Unmarshal(bodyBytes, &doc3)

	if strings.HasPrefix(doc3.OpenAPI, "3") {
		return &doc3
	} else if strings.HasPrefix(doc.Swagger, "2") {
		newDoc, err := openapi2conv.ToV3(&doc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error converting v2 document to v3: %s\n", err)
		}
		return newDoc
	} else if cfg.Mode == config.ModeBrute {
		return &openapi3.T{}
	} else {
		output.Die("Error parsing definition file.")
		return nil
	}
}
