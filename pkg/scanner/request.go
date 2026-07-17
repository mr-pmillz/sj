package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/url"
	"slices"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
)

func BuildRequestsFromPaths(spec map[string]any, client *httpclient.Client, cfg *config.Config, w *output.Writer, resolver *openapi.Resolver) {
	paths, ok := spec["paths"].(map[string]any)
	if !ok || paths == nil {
		output.Die("Could not find any defined operations. Review the file manually.")
	}

	pathKeys := make([]string, 0, len(paths))
	for k := range paths {
		pathKeys = append(pathKeys, k)
	}
	slices.Sort(pathKeys)

	userHeaders := append([]string(nil), cfg.Headers...)
	var userContentType string
	for _, h := range userHeaders {
		if strings.HasPrefix(strings.ToLower(h), "content-type:") {
			if _, after, ok0 := strings.Cut(h, ":"); ok0 {
				userContentType = strings.TrimSpace(after)
			}
			break
		}
	}

	for _, pathName := range pathKeys {
		pathItem := paths[pathName]
		ops, ok := pathItem.(map[string]any)
		if !ok {
			continue
		}
		methodKeys := make([]string, 0, len(ops))
		for k := range ops {
			methodKeys = append(methodKeys, k)
		}
		slices.Sort(methodKeys)
		for _, method := range methodKeys {
			op := ops[method]
			switch strings.ToLower(method) {
			case "delete", "patch":
				continue
			}

			opMap, ok := op.(map[string]any)
			if !ok {
				continue
			}

			cfg.Headers = append([]string(nil), userHeaders...)
			contentType := userContentType

			targetURL := fmt.Sprintf("%s%s%s", cfg.APITarget, cfg.BasePath, pathName)
			curl := fmt.Sprintf("curl -X %s \"%s\"", strings.ToUpper(method), targetURL)
			var bodyData string

			if params, ok := opMap["parameters"].([]any); ok {
				for _, p := range params {
					pMap, ok := p.(map[string]any)
					if !ok {
						continue
					}
					paramContextSpec := spec
					if ref, hasRef := pMap["$ref"].(string); hasRef {
						resolved, ctxSpec := resolver.ResolveRefWithContext(spec, ref)
						if resolved != nil {
							pMap = resolved
							paramContextSpec = ctxSpec
						}
					}

					name, _ := pMap["name"].(string)
					in, _ := pMap["in"].(string)
					if name == "" || in == "" {
						continue
					}

					var pValue string
					var handledAsObject bool

					if schema, ok := pMap["schema"].(map[string]any); ok {
						expanded := openapi.ExpandSchema(spec, schema, map[string]bool{}, paramContextSpec, resolver)
						if expanded.Type == "object" || len(expanded.Properties) > 0 {
							example := openapi.GenerateExample(expanded, cfg)
							if exampleMap, ok := example.(map[string]any); ok {
								switch in {
								case "query":
									for pi, pv := range exampleMap {
										sep := "&"
										if !strings.Contains(curl, "?") && !strings.Contains(targetURL, "?") {
											sep = "?"
										}
										targetURL += fmt.Sprintf("%s%s=%v", sep, pi, pv)
									}
									handledAsObject = true
								case "body":
									for pi, pv := range exampleMap {
										pVal := fmt.Sprintf("%v", pv)
										if strings.Contains(curl, "-d '") {
											bodyData += fmt.Sprintf("&%s=%s", pi, pVal)
											curl = strings.TrimSuffix(curl, "'")
											curl += fmt.Sprintf("&%s=%s'", pi, pVal)
										} else {
											bodyData += fmt.Sprintf("%s=%s", pi, pVal)
											curl += fmt.Sprintf(" -d '%s=%s'", pi, pVal)
										}
									}
									handledAsObject = true
								}
							}
						} else {
							exampleValue := openapi.GenerateExample(expanded, cfg)
							if expanded.Type == "string" && name != "version" {
								pValue = cfg.TestString
							} else if exampleValue != nil {
								pValue = fmt.Sprintf("%v", exampleValue)
							} else {
								pValue = "1"
							}
						}
					} else if pType, ok := pMap["type"].(string); ok {
						if defaultVal := pMap["default"]; defaultVal != nil {
							pValue = fmt.Sprintf("%v", defaultVal)
						} else if pType == "string" && name != "version" {
							pValue = cfg.TestString
						} else {
							pValue = "1"
						}
					} else if defaultVal := pMap["default"]; defaultVal != nil {
						pValue = fmt.Sprintf("%v", defaultVal)
					} else {
						pValue = "1"
					}

					if !handledAsObject {
						switch in {
						case "query":
							sep := "&"
							if !strings.Contains(curl, "?") && !strings.Contains(targetURL, "?") {
								sep = "?"
							}
							targetURL += fmt.Sprintf("%s%s=%s", sep, name, pValue)
						case "path":
							targetURL = strings.Replace(targetURL, "{"+name+"}", pValue, 1)
						case "header":
							curl += fmt.Sprintf(" -H \"%s: %s\"", name, pValue)
						case "body":
							if strings.Contains(curl, "-d '") {
								bodyData += fmt.Sprintf("&%s=%s", name, pValue)
								curl = strings.TrimSuffix(curl, "'")
								curl += fmt.Sprintf("&%s=%s'", name, pValue)
							} else {
								bodyData += fmt.Sprintf("%s=%s", name, pValue)
								curl += fmt.Sprintf(" -d '%s=%s'", name, pValue)
							}
						}
					}
				}
			}

			if reqBody, ok := opMap["requestBody"].(map[string]any); ok {
				reqBodyContextSpec := spec
				if ref, hasRef := reqBody["$ref"].(string); hasRef {
					resolved, ctxSpec := resolver.ResolveRefWithContext(spec, ref)
					if resolved != nil {
						reqBody = resolved
						reqBodyContextSpec = ctxSpec
					}
				}

				if contentTypes, ok := reqBody["content"].(map[string]any); ok {
					for cType := range contentTypes {
						if contentType == "" {
							cfg.Headers = EnforceSingleContentType(cfg.Headers, cType)
						} else {
							cfg.Headers = EnforceSingleContentType(cfg.Headers, contentType)
						}

						ct, ok := contentTypes[cType].(map[string]any)
						if !ok {
							continue
						}
						schema, ok := ct["schema"].(map[string]any)
						if !ok {
							continue
						}

						expanded := openapi.ExpandSchema(spec, schema, map[string]bool{}, reqBodyContextSpec, resolver)
						example := openapi.GenerateExample(expanded, cfg)

						switch cType {
						case "application/json":
							bodyBytes, err := json.Marshal(example)
							if err == nil {
								bodyData = string(bodyBytes)
								curl += fmt.Sprintf(" -H \"Content-Type: application/json\" -d '%s'", bodyBytes)
							}
						case "application/xml", "text/xml":
							if obj, ok := example.(map[string]any); ok {
								xml := XmlFromObject(obj)
								bodyData = xml
								curl += fmt.Sprintf(" -H \"Content-Type: %s\" -d '%s'", cType, xml)
							}
						case "application/x-www-form-urlencoded":
							if obj, ok := example.(map[string]any); ok {
								var formParts []string
								for k, v := range obj {
									formParts = append(formParts, fmt.Sprintf("%s=%v", k, v))
								}
								bodyData = strings.Join(formParts, "&")
								curl += fmt.Sprintf(" -H \"Content-Type: %s\" -d '%s'", cType, bodyData)
							}
						case "multipart/form-data":
							if obj, ok := example.(map[string]any); ok {
								var buf bytes.Buffer
								mw := multipart.NewWriter(&buf)
								for k, v := range obj {
									_ = mw.WriteField(k, fmt.Sprintf("%v", v))
								}
								_ = mw.Close()
								bodyData = buf.String()
								cfg.Headers = EnforceSingleContentType(cfg.Headers, mw.FormDataContentType())
								for k, v := range obj {
									curl += fmt.Sprintf(" -F \"%s=%v\"", k, v)
								}
							}
						}
					}
				}
			}

			curlParts := strings.SplitN(curl, "\"", 3)
			if len(curlParts) >= 3 {
				curl = curlParts[0] + "\"" + targetURL + "\"" + curlParts[2]
			}

			logURL, parseErr := url.Parse(targetURL)
			if parseErr != nil || logURL == nil {
				output.PrintWarn("Error parsing URL '%s': %v - skipping endpoint.", targetURL, parseErr)
				continue
			}

			switch cfg.Mode {
			case config.ModeAutomate:
				var postBodyData string
				if strings.ToLower(method) == "post" {
					postBodyData = bodyData
				}

				_, resp, sc := client.MakeRequest(strings.ToUpper(method), targetURL, bytes.NewReader([]byte(postBodyData)))

				if cfg.RetryOnHint && sc == 401 {
					resp, sc = RetryWithHints(client, cfg, strings.ToUpper(method), targetURL, postBodyData, resp, sc)
				}

				previewLen := min(len(resp), cfg.ResponsePreview)
				preview := resp[:previewLen]

				if cfg.Verbose {
					w.AddVerboseResult(output.VerboseResult{
						Method: method, Preview: preview, Status: sc, Target: logURL.Path, Curl: curl,
					})
				} else {
					w.AddResult(output.Result{
						Method: method, Status: sc, Target: logURL.Path,
					})
				}

				shouldRecord := !cfg.GetAccessibleEndpoints || sc == 200
				if shouldRecord {
					if cfg.GetAccessibleEndpoints {
						w.AccessibleEndpoints = append(w.AccessibleEndpoints, logURL.Path)
					}
					if cfg.OutputFormat == "console" {
						w.WriteLog(sc, logURL.Path, strings.ToUpper(method), preview)
					} else if cfg.ProgressDisplay {
						output.LogProgress(sc, logURL.Path, strings.ToUpper(method), preview)
					}
					if client.Replay != nil {
						client.ReplayRequest(strings.ToUpper(method), targetURL, bytes.NewReader([]byte(postBodyData)))
					}
				}

			case config.ModeEndpoints:
				fmt.Println(cfg.BasePath + pathName)

			case config.ModePrepare:
				var preparedCommand string = curl
				if strings.ToLower(cfg.PrepareFor) == "sqlmap" {
					preparedCommand = strings.Replace(preparedCommand, "curl", "sqlmap", 1)
					preparedCommand = strings.Replace(preparedCommand, "-X "+strings.ToUpper(method), "--method="+strings.ToUpper(method)+" -u", 1)
					if bodyData != "" {
						preparedCommand = strings.Replace(preparedCommand, "-d '"+bodyData+"'", "--data='"+bodyData+"'", 1)
					}
					preparedCommand = "$ " + preparedCommand
				} else if cfg.PrepareFor == "curl" {
					preparedCommand = "$ " + curl
				}
				fmt.Println(preparedCommand)
			}
		}
	}

	if cfg.Mode == config.ModeAutomate {
		ofmt := strings.ToLower(cfg.OutputFormat)
		if ofmt != "console" || cfg.OutputAllFormats {
			w.FinalizeOutput()
		}
	}
}
