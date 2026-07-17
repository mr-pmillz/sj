package openapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
	"gopkg.in/yaml.v3"
)

func ConvertSpec(body []byte, cfg *config.Config) error {
	converted, alreadyV3, err := ConvertToOpenAPI3(body, cfg.Format)
	if err != nil {
		return err
	}
	if alreadyV3 {
		output.PrintWarn("Definition file is already OpenAPI version 3.")
	}
	if cfg.Outfile == "" {
		_, err = os.Stdout.Write(append(converted, '\n'))
		if err != nil {
			return fmt.Errorf("write converted specification: %w", err)
		}
		return nil
	}
	if err := WriteConvertedFile(converted, cfg.Outfile); err != nil {
		return err
	}
	absolute, _ := filepath.Abs(cfg.Outfile)
	output.PrintInfo("Wrote file to %s\n", absolute)
	return nil
}

func ConvertToOpenAPI3(body []byte, outputFormat string) ([]byte, bool, error) {
	if extracted, ok := ExtractJSONFromJSSpec(body); ok {
		body = extracted
	}
	raw, err := SafelyUnmarshalSpec(body)
	if err != nil {
		return nil, false, err
	}
	version3, _ := raw["openapi"].(string)
	alreadyV3 := strings.HasPrefix(version3, "3")

	var document any = raw
	if !alreadyV3 {
		version2, _ := raw["swagger"].(string)
		if !strings.HasPrefix(version2, "2") {
			return nil, false, fmt.Errorf("document is neither Swagger 2 nor OpenAPI 3")
		}
		swagger, decodeErr := DecodeSwagger2(body)
		if decodeErr != nil {
			return nil, false, decodeErr
		}
		converted, convertErr := openapi2conv.ToV3(swagger)
		if convertErr != nil {
			return nil, false, fmt.Errorf("convert Swagger 2 document: %w", convertErr)
		}
		document = converted
	}

	switch strings.ToLower(outputFormat) {
	case "yaml", "yml":
		converted, marshalErr := yaml.Marshal(document)
		if marshalErr != nil {
			return nil, alreadyV3, fmt.Errorf("marshal OpenAPI YAML: %w", marshalErr)
		}
		return converted, alreadyV3, nil
	case "", "json", "js":
		converted, marshalErr := json.MarshalIndent(document, "", "  ")
		if marshalErr != nil {
			return nil, alreadyV3, fmt.Errorf("marshal OpenAPI JSON: %w", marshalErr)
		}
		return converted, alreadyV3, nil
	default:
		return nil, alreadyV3, fmt.Errorf("unsupported output format %q; use json or yaml", outputFormat)
	}
}

func WriteConvertedFile(data []byte, outfile string) error {
	if outfile == "" {
		return fmt.Errorf("output path is empty")
	}
	directory := filepath.Dir(outfile)
	temporary, err := os.CreateTemp(directory, ".sj-convert-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary output: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if err := os.Rename(temporaryPath, outfile); err != nil {
		return fmt.Errorf("publish converted output: %w", err)
	}
	return nil
}
