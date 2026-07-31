package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func decodeBoundedJSON(input []byte, limits Limits, output any) error {
	if len(input) > limits.MaxInputBytes {
		return fmt.Errorf("%w: input bytes", ErrLimitExceeded)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return fmt.Errorf("%w: decode JSON", ErrInvalidInput)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	count := 0
	if err := inspectJSONValue(generic, 0, &count, limits); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("%w: decode JSON shape", ErrInvalidInput)
	}
	return ensureJSONEOF(decoder)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: multiple JSON values", ErrInvalidInput)
	}
	return nil
}

func inspectJSONValue(value any, depth int, nodes *int, limits Limits) error {
	*nodes++
	if *nodes > limits.MaxNodes {
		return fmt.Errorf("%w: JSON nodes", ErrLimitExceeded)
	}
	switch typed := value.(type) {
	case map[string]any:
		if depth >= limits.MaxDepth {
			return fmt.Errorf("%w: JSON depth", ErrLimitExceeded)
		}
		for _, child := range typed {
			if err := inspectJSONValue(child, depth+1, nodes, limits); err != nil {
				return err
			}
		}
	case []any:
		if depth >= limits.MaxDepth {
			return fmt.Errorf("%w: JSON depth", ErrLimitExceeded)
		}
		for _, child := range typed {
			if err := inspectJSONValue(child, depth+1, nodes, limits); err != nil {
				return err
			}
		}
	}
	return nil
}
