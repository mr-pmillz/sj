package openapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Resolver struct {
	ExternalRefCache map[string]map[string]any
	BaseDir          string
}

func NewResolver(baseDir string) *Resolver {
	return &Resolver{
		ExternalRefCache: make(map[string]map[string]any),
		BaseDir:          baseDir,
	}
}

func (r *Resolver) ResolveRef(spec map[string]any, ref string) map[string]any {
	resolved, _ := r.ResolveRefWithContext(spec, ref)
	return resolved
}

func (r *Resolver) ResolveRefWithContext(spec map[string]any, ref string) (map[string]any, map[string]any) {
	if !strings.HasPrefix(ref, "#") {
		baseDir := r.BaseDir
		for cachedPath, cachedSpec := range r.ExternalRefCache {
			if fmt.Sprintf("%p", cachedSpec) == fmt.Sprintf("%p", spec) {
				baseDir = filepath.Dir(cachedPath)
				break
			}
		}

		resolved := r.ResolveExternalRef(ref, baseDir)
		if resolved != nil {
			filePath := strings.SplitN(ref, "#", 2)[0]
			fullPath := filepath.Clean(filepath.Join(baseDir, filePath))
			if externalSpec, exists := r.ExternalRefCache[fullPath]; exists {
				return resolved, externalSpec
			}
		}
		return resolved, spec
	}

	parts := strings.Split(ref[2:], "/")
	var cur any = spec

	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, spec
		}
		cur = m[p]
	}

	resolved, _ := cur.(map[string]any)
	return resolved, spec
}

func (r *Resolver) ResolveExternalRef(ref string, baseDir string) map[string]any {
	parts := strings.SplitN(ref, "#", 2)
	if len(parts) < 1 {
		return nil
	}

	relativePath := parts[0]
	var jsonPointer string
	if len(parts) == 2 {
		jsonPointer = parts[1]
	}

	filePath := filepath.Join(baseDir, relativePath)
	filePath = filepath.Clean(filePath)

	if cached, exists := r.ExternalRefCache[filePath]; exists {
		if jsonPointer == "" {
			return cached
		}
		return r.ResolveRef(cached, "#"+jsonPointer)
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	externalSpec := MustUnmarshalSpec(fileData)
	if externalSpec == nil {
		return nil
	}

	r.ExternalRefCache[filePath] = externalSpec

	if jsonPointer == "" {
		return externalSpec
	}
	return r.ResolveRef(externalSpec, "#"+jsonPointer)
}
