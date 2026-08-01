package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"gopkg.in/yaml.v3"
)

func Load(path string, options LoadOptions) (model.Manifest, error) {
	options = options.withDefaults()
	file, err := openRegularFile(path, options.MaxManifestBytes)
	if err != nil {
		return model.Manifest{}, fmt.Errorf("load assessment manifest: %w", err)
	}
	data, readErr := readBounded(file, options.MaxManifestBytes)
	closeErr := file.Close()
	if readErr != nil {
		failure := fmt.Errorf("load assessment manifest: %w", readErr)
		if closeErr != nil {
			failure = errors.Join(failure, fmt.Errorf("close assessment manifest: %w", closeErr))
		}
		return model.Manifest{}, failure
	}
	if closeErr != nil {
		return model.Manifest{}, fmt.Errorf("close assessment manifest: %w", closeErr)
	}
	return parse(data, options)
}

func Parse(data []byte, options LoadOptions) (model.Manifest, error) {
	options = options.withDefaults()
	if int64(len(data)) > options.MaxManifestBytes {
		return model.Manifest{}, ErrManifestTooLarge
	}
	return parse(data, options)
}

func parse(data []byte, options LoadOptions) (model.Manifest, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return model.Manifest{}, fmt.Errorf("%w: %w", ErrDecode, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return model.Manifest{}, fmt.Errorf("%w: multiple YAML documents are not allowed", ErrDecode)
		}
		return model.Manifest{}, fmt.Errorf("%w: %w", ErrDecode, err)
	}

	result, err := validateAndBuild(decoded, options)
	if err != nil {
		return model.Manifest{}, err
	}
	return result, nil
}

func openRegularFile(path string, maxBytes int64) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect file: %w", ErrUnsafeFile, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: path must be a regular non-symlink file", ErrUnsafeFile)
	}
	if before.Size() > maxBytes {
		return nil, ErrManifestTooLarge
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, closeAfterFailure(file, fmt.Errorf("stat opened file: %w", err))
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, closeAfterFailure(file, fmt.Errorf("%w: file changed while opening", ErrUnsafeFile))
	}
	return file, nil
}

func closeAfterFailure(file *os.File, failure error) error {
	if err := file.Close(); err != nil {
		return errors.Join(failure, fmt.Errorf("close file after failure: %w", err))
	}
	return failure
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded input: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrManifestTooLarge
	}
	return data, nil
}
