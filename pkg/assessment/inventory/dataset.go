package inventory

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mr-pmillz/sj/pkg/report"
)

type DatasetOptions struct {
	SourceHash string
	Limits     Limits
}

func ImportDataset(ctx context.Context, dataset report.Dataset, options DatasetOptions) (Inventory, error) {
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	limits := options.Limits.withDefaults()
	if err := limits.validate(); err != nil {
		return Inventory{}, err
	}
	if len(dataset.Operations) > limits.MaxOperations {
		return Inventory{}, fmt.Errorf("%w: dataset operations exceed %d", ErrLimitExceeded, limits.MaxOperations)
	}
	for _, operation := range dataset.Operations {
		for _, value := range []string{operation.Source, operation.Method, operation.Target, operation.URL, operation.BaselineURL, operation.ContentType, operation.Identity, operation.Case, operation.Category, operation.Guidance} {
			if len(value) > limits.MaxStringBytes {
				return Inventory{}, fmt.Errorf("%w: dataset field exceeds %d bytes", ErrLimitExceeded, limits.MaxStringBytes)
			}
		}
	}
	sourceHash := strings.ToLower(strings.TrimSpace(options.SourceHash))
	if sourceHash != "" {
		decoded, err := hex.DecodeString(sourceHash)
		if err != nil || len(decoded) != 32 {
			return Inventory{}, fmt.Errorf("dataset source hash must be a 64-character SHA-256")
		}
	} else {
		var err error
		sourceHash, err = hashDatasetMetadata(dataset.Operations)
		if err != nil {
			return Inventory{}, err
		}
	}

	operations := make([]Operation, 0, len(dataset.Operations))
	for index, observed := range dataset.Operations {
		if err := ctx.Err(); err != nil {
			return Inventory{}, err
		}
		actualURL := observed.URL
		if actualURL == "" {
			actualURL = observed.Target
		}
		origin, actualPath, query := normalizeObservedURL(actualURL)
		templateURL := observed.BaselineURL
		if templateURL == "" {
			templateURL = actualURL
		}
		templateOrigin, templatePath, _ := normalizeObservedURL(templateURL)
		if origin == "" {
			origin = templateOrigin
		}
		if templatePath == "" {
			templatePath = actualPath
		}
		if templatePath == "" {
			templatePath = "/"
		}
		method := strings.ToUpper(strings.TrimSpace(observed.Method))
		sourcePointer := fmt.Sprintf("/operations/%d", index)
		source := Source{Kind: "report-dataset", Reference: observed.Source, DocumentVersion: "sj-report", SHA256: sourceHash}
		response := Response{Status: fmt.Sprintf("%d", observed.Status), JSONPointer: sourcePointer}
		if observed.ContentType != "" {
			response.MediaTypes = []string{observed.ContentType}
		}
		operation := Operation{
			Source:            source,
			SourcePointer:     sourcePointer,
			Surface:           SurfaceObserved,
			Method:            method,
			Origin:            origin,
			PathTemplate:      templatePath,
			ObservedServerURL: redactObservedURL(actualURL),
			ObservedQuery:     query,
			ObservedStatus:    observed.Status,
			ObservedIdentity:  observed.Identity,
			ObservedCase:      observed.Case,
			ActiveAuthorized:  false,
			RiskClass:         methodRisk(method),
			Responses:         []Response{response},
		}
		operation.ID = stableOperationID(sourceHash, method, origin, "", templatePath, sourcePointer)
		operations = append(operations, operation)
	}
	return newInventory(operations), nil
}

func hashDatasetMetadata(operations []report.Operation) (string, error) {
	type metadata struct {
		Source       string
		Method       string
		Status       int
		Target       string
		URL          string
		BaselineURL  string
		ContentType  string
		Case         string
		Category     string
		Identity     string
		WasTruncated bool
	}
	values := make([]metadata, len(operations))
	for index, operation := range operations {
		values[index] = metadata{
			Source: operation.Source, Method: operation.Method, Status: operation.Status,
			Target: operation.Target, URL: operation.URL, BaselineURL: operation.BaselineURL,
			ContentType: operation.ContentType, Case: operation.Case, Category: operation.Category,
			Identity: operation.Identity, WasTruncated: operation.ResponseTruncated,
		}
	}
	return hashValue(values)
}
