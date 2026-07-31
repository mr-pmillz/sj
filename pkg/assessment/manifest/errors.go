// Package manifest loads and validates versioned assessment manifests without
// resolving credential material.
package manifest

import "errors"

var (
	ErrDecode           = errors.New("decode assessment manifest")
	ErrManifestTooLarge = errors.New("assessment manifest exceeds size limit")
	ErrValidation       = errors.New("invalid assessment manifest")
	ErrSecretReference  = errors.New("invalid secret reference")
	ErrUnsafeFile       = errors.New("unsafe file")
)

const (
	DefaultMaxManifestBytes   int64 = 1 << 20
	DefaultMaxSecretFileBytes int64 = 64 << 10
	DefaultMaxInputFileBytes  int64 = 64 << 20
)

type LoadOptions struct {
	MaxManifestBytes   int64
	MaxSecretFileBytes int64
	MaxInputFileBytes  int64
}

func (o LoadOptions) withDefaults() LoadOptions {
	if o.MaxManifestBytes <= 0 {
		o.MaxManifestBytes = DefaultMaxManifestBytes
	}
	if o.MaxSecretFileBytes <= 0 {
		o.MaxSecretFileBytes = DefaultMaxSecretFileBytes
	}
	if o.MaxInputFileBytes <= 0 {
		o.MaxInputFileBytes = DefaultMaxInputFileBytes
	}
	return o
}
