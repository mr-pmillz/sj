package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/url"
	"slices"
	"strings"
)

func (c Case) requestBody() ([]byte, string, error) {
	switch {
	case c.Body != "" || c.ContentType != "":
		if c.JSONBody != "" || c.Form != "" || c.Multipart != nil {
			return nil, "", errors.New("choose one body representation")
		}
		if c.ContentType != "" {
			if _, _, err := mime.ParseMediaType(c.ContentType); err != nil {
				return nil, "", errors.New("contentType must be a media type")
			}
		}
		return []byte(c.Body), c.ContentType, nil
	case c.JSONBody != "":
		if c.Form != "" || c.Multipart != nil {
			return nil, "", errors.New("choose one body representation")
		}
		if !json.Valid([]byte(c.JSONBody)) {
			return nil, "", errors.New("jsonBody must contain one valid JSON value")
		}
		return []byte(c.JSONBody), "application/json", nil
	case c.Form != "":
		if c.Multipart != nil {
			return nil, "", errors.New("choose one body representation")
		}
		values, err := url.ParseQuery(c.Form)
		if err != nil {
			return nil, "", errors.New("form must be URL-encoded")
		}
		return []byte(values.Encode()), "application/x-www-form-urlencoded", nil
	case c.Multipart != nil:
		return multipartBody(c.Multipart)
	default:
		return nil, "", nil
	}
}

func multipartBody(parts map[string]Part) ([]byte, string, error) {
	var data bytes.Buffer
	writer := multipart.NewWriter(&data)
	for _, name := range slices.Sorted(maps.Keys(parts)) {
		part := parts[name]
		if name == "" || strings.ContainsAny(name+part.Filename, "\r\n\x00") {
			return nil, "", errors.New("invalid multipart name or filename")
		}
		if part.Filename == "" {
			if err := writer.WriteField(name, part.Value); err != nil {
				return nil, "", err
			}
			continue
		}
		field, err := writer.CreateFormFile(name, part.Filename)
		if err != nil {
			return nil, "", err
		}
		if _, err := io.WriteString(field, part.Value); err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return data.Bytes(), writer.FormDataContentType(), nil
}
