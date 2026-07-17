package brute

// PrefixDirs are common directory prefixes where API documentation may live.
var PrefixDirs = []string{
	"",
	"/swagger", "/swagger/docs", "/swagger/latest",
	"/swagger/v1", "/swagger/v2", "/swagger/v3",
	"/swagger/static", "/swagger/ui",
	"/swagger-ui",
	"/api-docs", "/api-docs/v1", "/api-docs/v2",
	"/apidocs",
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/v1", "/v2", "/v3",
	"/doc",
	"/docs", "/docs/swagger", "/docs/swagger/v1", "/docs/swagger/v2",
	"/docs/swagger-ui", "/docs/swagger-ui/v1", "/docs/swagger-ui/v2",
	"/docs/v1", "/docs/v2", "/docs/v3",
	"/public",
	"/redoc",
}

// JSONEndpoints are filenames commonly served as JSON API specs.
var JSONEndpoints = []string{
	"", "/index",
	"/swagger", "/swagger-ui", "/swagger-resources", "/swagger-config",
	"/openapi",
	"/api", "/api-docs", "/apidocs",
	"/v1", "/v2", "/v3",
	"/doc", "/docs",
	"/apispec", "/apispec_1", "/api-merged",
}

// JavaScriptEndpoints are JS bundles that may contain embedded specs.
var JavaScriptEndpoints = []string{
	"/swagger-ui-init",
	"/swagger-ui-bundle",
	"/swagger-ui-standalone-preset",
	"/swagger-ui",
	"/swagger-ui.min",
	"/swagger-ui-es-bundle-core",
	"/swagger-ui-es-bundle",
	"/swagger-ui-standalone-preset",
	"/swagger-ui-layout",
	"/swagger-ui-plugins",
}

// PriorityURLs are well-known full paths that are tested first.
var PriorityURLs = []string{
	"/swagger.json", "/openapi.json", "/api-docs", "/swagger", "/docs",
	"/api/swagger.json", "/api/openapi.json", "/api-docs/swagger.json",
	"/api/schema/", "/webjars/swagger-ui/index.html",
	"/API/swagger/ui/index", "/swagger/ui/index",
	"/v2/swagger.json", "/v2/openapi.json", "/v2/api-docs",
	"/v3/api-docs", "/v3/openapi.json",
	"/public/api-merged.json",
	"/analytics/v1/swagger", "/api.json",
	"/api/4.0/swagger.json",
	"/api/api-doc/openapi.json", "/api/api-doc/openapi.yaml",
	"/api/doc.json", "/api/docs.json",
	"/api/swagger", "/api/swagger/ui/index",
	"/api/v1/swagger", "/api/v2/api-docs", "/api/v2/openapi.json",
	"/api/v2/swagger.json", "/api/v3/api-docs", "/api/v3/apispec",
	"/api/workorder/openapi.json",
	"/apidocs",
	"/audiences/v1/swagger", "/audittrail/v1/swagger",
	"/certification/v1/swagger",
	"/citrixapi/store/swagger.json",
	"/conferencetool/v1/swagger", "/course/v1/swagger",
	"/dcl_swagger.yaml",
	"/doc/doc.json", "/doc/swagger.json",
	"/docs/swagger.json", "/docs/v1/swagger.json",
	"/ecommerce/v1/swagger", "/enrollment/v1/swagger",
	"/externalids/v1/swagger",
	"/impact/v1/swagger",
	"/learn/v1/swagger", "/learningplan/v1/swagger",
	"/manage/v1/swagger", "/management/info",
	"/marketplace/v1/swagger", "/messenger/v1/swagger",
	"/notifications/v1/swagger",
	"/openapi", "/openapi/spec.json",
	"/otj/v1/swagger",
	"/pages/v1/swagger", "/poweruser/v1/swagger",
	"/proctoring/v1/swagger",
	"/report/v1/swagger",
	"/swagger-ui/index.html", "/swagger-ui/openapi.json",
	"/swagger.yaml",
	"/swagger/0.1.0/swagger.json", "/swagger/doc.json",
	"/swagger/latest/swagger.json", "/swagger/swagger.json",
	"/swagger/test/swagger.json", "/swagger/ui/index.html",
	"/swagger/v1/openapiv2.json", "/swagger/v1/swagger.json",
	"/swagger/v2/swagger.json", "/swagger/v4/swagger.json",
	"/v1/openapi.json", "/v1/swagger", "/v1/swagger.json",
	"/swagger/docs/v1", "/swagger/docs/v1.json",
	"/Api/swagger/docs/v1",
	"/api/api-docs/swagger.json",
	"/api/docs/", "/api/docs",
	"/swagger-ui",
}

// MakeURLs builds a list of candidate URLs by combining a target, base path,
// prefix directories, and endpoint filenames.
func MakeURLs(target, basePath string, endpoints []string, fileExtension string, skipPrefix bool) []string {
	var urls []string
	if !skipPrefix {
		for _, dir := range PrefixDirs {
			for _, endpoint := range endpoints {
				if dir == "" && endpoint == "" {
					continue
				}
				urls = append(urls, target+basePath+dir+endpoint+fileExtension)
			}
		}
	} else {
		for _, endpoint := range endpoints {
			if endpoint == "" {
				continue
			}
			urls = append(urls, target+basePath+endpoint+fileExtension)
		}
	}
	return urls
}
