package openapi

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const maxExternalSpecBytes int64 = 10 * 1024 * 1024

// Resolver resolves JSON references. External files are disabled when BaseDir
// is empty and, when enabled, are confined to the original BaseDir tree.
type Resolver struct {
	ExternalRefCache map[string]map[string]any
	BaseDir          string
	mu               sync.RWMutex
}

func NewResolver(baseDir string) *Resolver {
	resolver := &Resolver{ExternalRefCache: make(map[string]map[string]any)}
	if baseDir == "" {
		return resolver
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return resolver
	}
	if evaluated, evalErr := filepath.EvalSymlinks(abs); evalErr == nil {
		abs = evaluated
	}
	resolver.BaseDir = filepath.Clean(abs)
	return resolver
}

func (r *Resolver) ResolveRef(spec map[string]any, ref string) map[string]any {
	resolved, _ := r.ResolveRefWithContext(spec, ref)
	return resolved
}

func (r *Resolver) ResolveRefWithContext(spec map[string]any, ref string) (map[string]any, map[string]any) {
	if ref == "#" {
		return spec, spec
	}
	if !strings.HasPrefix(ref, "#") {
		baseDir := r.baseForSpec(spec)
		resolved, externalSpec := r.resolveExternalRef(ref, baseDir)
		if resolved == nil {
			return nil, spec
		}
		return resolved, externalSpec
	}
	if !strings.HasPrefix(ref, "#/") {
		return nil, spec
	}

	var current any = spec
	for _, encoded := range strings.Split(ref[2:], "/") {
		part, ok := decodeJSONPointerToken(encoded)
		if !ok {
			return nil, spec
		}
		switch value := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = value[part]
			if !exists {
				return nil, spec
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(value) {
				return nil, spec
			}
			current = value[index]
		default:
			return nil, spec
		}
	}

	resolved, _ := current.(map[string]any)
	return resolved, spec
}

func decodeJSONPointerToken(token string) (string, bool) {
	var builder strings.Builder
	for index := 0; index < len(token); index++ {
		if token[index] != '~' {
			builder.WriteByte(token[index])
			continue
		}
		if index+1 >= len(token) {
			return "", false
		}
		index++
		switch token[index] {
		case '0':
			builder.WriteByte('~')
		case '1':
			builder.WriteByte('/')
		default:
			return "", false
		}
	}
	return builder.String(), true
}

func (r *Resolver) baseForSpec(spec map[string]any) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for cachedPath, cachedSpec := range r.ExternalRefCache {
		if fmt.Sprintf("%p", cachedSpec) == fmt.Sprintf("%p", spec) {
			return filepath.Dir(cachedPath)
		}
	}
	return r.BaseDir
}

func (r *Resolver) ResolveExternalRef(ref string, baseDir string) map[string]any {
	resolved, _ := r.resolveExternalRef(ref, baseDir)
	return resolved
}

func (r *Resolver) resolveExternalRef(ref, baseDir string) (map[string]any, map[string]any) {
	parsedRef, _ := url.Parse(ref)
	if r.BaseDir == "" || parsedRef.Scheme != "" || parsedRef.Host != "" {
		return nil, nil
	}
	parts := strings.SplitN(ref, "#", 2)
	relativePath := parts[0]
	if relativePath == "" {
		return nil, nil
	}
	jsonPointer := ""
	if len(parts) == 2 {
		jsonPointer = parts[1]
	}

	filePath, ok := r.confinedPath(relativePath, baseDir)
	if !ok {
		return nil, nil
	}
	r.mu.RLock()
	externalSpec, exists := r.ExternalRefCache[filePath]
	r.mu.RUnlock()
	if !exists {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, nil
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxExternalSpecBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || int64(len(data)) > maxExternalSpecBytes {
			return nil, nil
		}
		externalSpec, err = SafelyUnmarshalSpec(data)
		if err != nil || externalSpec == nil {
			return nil, nil
		}
		if err := ValidateReferencePolicy(externalSpec, r); err != nil {
			return nil, nil
		}
		r.mu.Lock()
		if cached, cachedExists := r.ExternalRefCache[filePath]; cachedExists {
			externalSpec = cached
		} else {
			r.ExternalRefCache[filePath] = externalSpec
		}
		r.mu.Unlock()
	}

	if jsonPointer == "" {
		return externalSpec, externalSpec
	}
	resolved, _ := r.ResolveRefWithContext(externalSpec, "#"+jsonPointer)
	return resolved, externalSpec
}

func (r *Resolver) confinedPath(relativePath, baseDir string) (string, bool) {
	if baseDir == "" {
		baseDir = r.BaseDir
	}
	if !filepath.IsAbs(baseDir) {
		baseDir = filepath.Join(r.BaseDir, baseDir)
	}
	candidate := relativePath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(baseDir, candidate)
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", false
	}
	evaluated, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(r.BaseDir, evaluated)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.Clean(evaluated), true
}
