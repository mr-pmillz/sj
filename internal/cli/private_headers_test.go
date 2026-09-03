package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

func TestRunAutomateScopesPrivateHeadersToExplicitOrigins(t *testing.T) {
	const (
		privateName  = "X-SJ-Private-7f4c1f"
		privateValue = "sentinel-9d2e8a"
	)
	var operationHeader atomic.Value
	operationHeader.Store("")
	operationServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		operationHeader.Store(request.Header.Get(privateName))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(operationServer.Close)

	var specificationHeader atomic.Value
	specificationHeader.Store("")
	specificationServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		specificationHeader.Store(request.Header.Get(privateName))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"openapi":"3.0.3","info":{"title":"private header test","version":"1"},"servers":[{"url":%q}],"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`, operationServer.URL)
	}))
	t.Cleanup(specificationServer.Close)

	headerPath := writeCLIPrivateHeaderFile(t, privateName+": "+privateValue+"\n")
	outputPath := filepath.Join(t.TempDir(), "automate.json")
	databasePath := filepath.Join(t.TempDir(), "results.db")
	cfg := config.New()
	cfg.DatabasePath = databasePath
	cfg.SwaggerURL = specificationServer.URL
	cfg.HeaderFile = headerPath
	cfg.OutputFormat = "json"
	cfg.Outfile = outputPath
	stdout, stderr, runErr := captureCLIStreams(t, func() error {
		return runAutomate(t.Context(), cfg)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if got := specificationHeader.Load().(string); got != privateValue {
		t.Fatalf("explicit specification origin received %q", got)
	}
	if got := operationHeader.Load().(string); got != "" {
		t.Fatalf("OpenAPI-derived second origin received private header %q", got)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{privateName, privateValue} {
		if strings.Contains(string(contents), forbidden) {
			t.Fatalf("automate output disclosed private header material: %s", contents)
		}
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatal("automate console output disclosed private header material")
		}
	}
	database, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{privateName, privateValue} {
		if strings.Contains(string(database), forbidden) {
			t.Fatalf("SQLite disclosed private header material %q", forbidden)
		}
	}
}

func TestRunAutomateDeliversPrivateHeadersToSameOriginOperations(t *testing.T) {
	const (
		privateName = "X-SJ-Private"
		sentinel    = "same-origin-private-42ca"
	)
	var operationHeader atomic.Value
	operationHeader.Store("")
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/items" {
			operationHeader.Store(request.Header.Get(privateName))
			_, _ = fmt.Fprintf(writer, `{"echo":%q,"header":%q}`, sentinel, privateName)
			return
		}
		_, _ = fmt.Fprintf(writer, `{"openapi":"3.0.3","info":{"title":"private header test","version":"1"},"servers":[{"url":%q}],"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`, server.URL)
	}))
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.NoDatabase = true
	cfg.SwaggerURL = server.URL + "/openapi.json"
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, privateName+": "+sentinel+"\n")
	cfg.OutputFormat = "json"
	artifactDirectory := t.TempDir()
	cfg.Outfile = filepath.Join(artifactDirectory, "automate.json")
	cfg.StoreResponses = true
	cfg.Verbose = true
	stdout, stderr, runErr := captureCLIStreams(t, func() error {
		return runAutomate(t.Context(), cfg)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if got := operationHeader.Load().(string); got != sentinel {
		t.Fatalf("same-origin operation received private header %q", got)
	}
	contents, err := os.ReadFile(cfg.Outfile)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{privateName, sentinel} {
		if strings.Contains(string(contents), forbidden) {
			t.Fatalf("reflected private material reached automate output: %s", contents)
		}
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("reflected private material reached automate console output")
		}
	}

	collectionCfg := *cfg
	collectionCfg.Outfile = filepath.Join(artifactDirectory, "bruno")
	reportCfg := *cfg
	reportCfg.Outfile = filepath.Join(artifactDirectory, "report")
	stdout, stderr, runErr = captureCLIStreams(t, func() error {
		if err := runCollection(t.Context(), &collectionCfg, collectionCLIOptions{
			Inputs: []string{cfg.Outfile}, Scope: "all", Name: "private-header-test",
			MaxOperations: 100, MaxRequests: 500, MaxInputBytes: 1 << 20,
			MaxFiles: 100, MaxRecords: 1_000,
		}); err != nil {
			return err
		}
		return runReport(t.Context(), &reportCfg, reportCLIOptions{
			Inputs: []string{cfg.Outfile}, AllFormats: true, Format: "terminal",
			Title: "Private header non-disclosure", MaxInputBytes: 1 << 20,
			MaxFiles: 100, MaxRecords: 1_000, MaxEvidence: 100,
		})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	for _, forbidden := range []string{privateName, sentinel} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatal("downstream report or collection console output disclosed private material")
		}
		assertDirectoryOmits(t, artifactDirectory, forbidden)
	}
}

func TestRunAutomateFailsBeforeNetworkWhenPrivateHeaderLoadFails(t *testing.T) {
	const sentinel = "sentinel-private-42ca"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	cfg := config.New()
	cfg.NoDatabase = true
	cfg.SwaggerURL = server.URL
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, "invalid "+sentinel+"\n")
	err := runAutomate(t.Context(), cfg)
	if err == nil {
		t.Fatal("automate accepted invalid private header file")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error disclosed private file contents: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server received %d requests after private-header failure", got)
	}
}

func TestRunBruteDeliversPrivateHeadersToExplicitTarget(t *testing.T) {
	const sentinel = "brute-private-42ca"
	var received atomic.Value
	received.Store("")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received.Store(request.Header.Get("X-SJ-Private"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"openapi":"3.0.3","info":{"title":%q,"version":"1"},"paths":{}}`, "X-SJ-Private "+sentinel)
	}))
	t.Cleanup(server.Close)
	wordlist := filepath.Join(t.TempDir(), "wordlist.txt")
	if err := os.WriteFile(wordlist, []byte("openapi.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.NoDatabase = true
	cfg.SwaggerURL = server.URL
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, "X-SJ-Private: "+sentinel+"\n")
	cfg.EndpointWordlist = wordlist
	cfg.MaxCandidates = 10
	cfg.BruteOutputFormat = "json"
	cfg.Outfile = filepath.Join(t.TempDir(), "brute.json")
	stdout, stderr, runErr := captureCLIStreams(t, func() error {
		return runBrute(t.Context(), cfg)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if got := received.Load().(string); got != sentinel {
		t.Fatalf("brute target received private header %q", got)
	}
	for _, output := range []string{stdout, stderr} {
		if strings.Contains(output, "X-SJ-Private") || strings.Contains(output, sentinel) {
			t.Fatal("brute console output disclosed reflected private material")
		}
	}
}

func TestFullWorkflowThreadsPrivatePolicyThroughActiveStages(t *testing.T) {
	const sentinel = "workflow-private-42ca"
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("https://api.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := config.New()
	base.NoDatabase = true
	base.HeaderFile = writeCLIPrivateHeaderFile(t, "X-SJ-Private: "+sentinel+"\n")
	assertTransport := func(stage string, stageCfg *config.Config) {
		t.Helper()
		if stageCfg.PrivateHeaders == nil || len(stageCfg.Headers) != 0 {
			t.Fatalf("%s did not retain an isolated private policy", stage)
		}
		client := httpclient.NewClient(stageCfg)
		if client.InitErr != nil {
			t.Fatal(client.InitErr)
		}
		var received string
		if err := client.ReplaceHTTPTransport(cliRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			received = request.Header.Get("X-SJ-Private")
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: http.NoBody, Request: request,
			}, nil
		}), true); err != nil {
			t.Fatal(err)
		}
		_, _, _ = client.MakeRequest(http.MethodGet, "https://api.example.test/resource", nil)
		if received != sentinel {
			t.Fatalf("%s transport received private header %q", stage, received)
		}
	}
	stages := fullWorkflowStages{
		brute: func(_ context.Context, stageCfg *config.Config) error {
			assertTransport("brute", stageCfg)
			return nil
		},
		automate: func(_ context.Context, stageCfg *config.Config) error {
			assertTransport("automate", stageCfg)
			return nil
		},
		fuzz: func(_ context.Context, stageCfg *config.Config, _ fuzzCLIOptions) error {
			assertTransport("fuzz", stageCfg)
			return nil
		},
		collection: func(context.Context, *config.Config, collectionCLIOptions) error { return nil },
		report:     func(context.Context, *config.Config, reportCLIOptions) error { return nil },
	}
	err := executeFullWorkflow(t.Context(), base, fullWorkflowCLIOptions{
		FullWorkflow: true, TargetsFile: targets, OutputDirectory: filepath.Join(t.TempDir(), "workflow"),
		Workers: 1, IDORRange: "1-3", MaxFuzzRequests: 20, MaxCases: 8, Delay: 500 * time.Millisecond,
	}, stages)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStoredRunOriginsDoNotAuthorizePrivateHeaders(t *testing.T) {
	cfg := config.New()
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, "X-SJ-Private: value\n")
	cfg.AutomateRunIDs = []string{"retained-run"}
	sources := []automateSource{{url: "https://stored.example.test/openapi.json"}}
	if err := loadPrivateHeaders(cfg, automateExplicitURLs(cfg, sources)); err == nil {
		t.Fatal("stored run URL silently expanded the private-header origin allowlist")
	}
}

func TestExplicitTargetAuthorizesPrivateHeadersForLocalSpecification(t *testing.T) {
	cfg := config.New()
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, "X-SJ-Private: value\n")
	cfg.APITarget = "https://api.example.test"
	cfg.TargetExplicit = true
	if err := loadPrivateHeaders(cfg, nil); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://api.example.test/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PrivateHeaders.Apply(request) || request.Header.Get("X-SJ-Private") != "value" {
		t.Fatal("explicit --target origin did not receive private headers")
	}
}

func TestRedactPrivateErrorDropsTheSensitiveCause(t *testing.T) {
	const sentinel = "error-private-42ca"
	cfg := config.New()
	cfg.HeaderFile = writeCLIPrivateHeaderFile(t, "X-SJ-Private: "+sentinel+"\n")
	if err := loadPrivateHeaders(cfg, []string{"https://api.example.test"}); err != nil {
		t.Fatal(err)
	}
	sanitized := redactPrivateError(cfg, fmt.Errorf("server reflected %s", sentinel))
	if strings.Contains(sanitized.Error(), sentinel) {
		t.Fatalf("redacted error disclosed private material: %v", sanitized)
	}
	if errors.Unwrap(sanitized) != nil {
		t.Fatal("redacted error retained its sensitive cause")
	}
}

func TestPrivateHeaderProcessArgvContainsOnlyTheFilePath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process argv inspection uses Linux /proc")
	}
	const (
		privateName  = "X-SJ-Argv-Private-7f4c1f"
		privateValue = "argv-private-sentinel-9d2e8a"
	)
	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	var received atomic.Value
	received.Store("")
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
	t.Cleanup(release)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received.Store(request.Header.Get(privateName))
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/items" {
			_, _ = writer.Write([]byte(`{"ok":true}`))
			return
		}
		close(requestStarted)
		<-releaseResponse
		_, _ = fmt.Fprintf(writer, `{"openapi":"3.0.3","info":{"title":"argv test","version":"1"},"servers":[{"url":%q}],"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`, server.URL)
	}))
	t.Cleanup(server.Close)

	headerPath := writeCLIPrivateHeaderFile(t, privateName+": "+privateValue+"\n")
	//nolint:gosec // G204: the executable is this test binary and every argument is test-generated.
	command := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestPrivateHeaderProcessArgvHelper$", "--",
		"automate", "-u", server.URL, "--header-file", headerPath,
	)
	command.Env = append(os.Environ(), "SJ_PRIVATE_HEADER_ARGV_HELPER=1")
	var processOutput strings.Builder
	command.Stdout = &processOutput
	command.Stderr = &processOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-requestStarted:
	case err := <-done:
		t.Fatalf("helper exited before request inspection: %v: %s", err, processOutput.String())
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not reach the target request")
	}
	if got := received.Load().(string); got != privateValue {
		t.Fatalf("helper target received private header %q", got)
	}

	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", command.Process.Pid))
	if err != nil {
		release()
		<-done
		t.Fatal(err)
	}
	arguments := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
	pathFound := false
	for index, argument := range arguments {
		if argument == "--header-file" && index+1 < len(arguments) && arguments[index+1] == headerPath {
			pathFound = true
		}
	}
	if !pathFound {
		t.Fatalf("process argv omitted --header-file path: %q", arguments)
	}
	for _, forbidden := range []string{privateName, privateValue} {
		if strings.Contains(string(cmdline), forbidden) {
			t.Fatalf("process argv disclosed private file material %q", forbidden)
		}
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("helper failed: %v: %s", err, processOutput.String())
	}
}

func TestPrivateHeaderProcessArgvHelper(t *testing.T) {
	if os.Getenv("SJ_PRIVATE_HEADER_ARGV_HELPER") != "1" {
		return
	}
	arguments := os.Args
	urlValue := commandLineValue(arguments, "-u")
	headerPath := commandLineValue(arguments, "--header-file")
	if urlValue == "" || headerPath == "" {
		t.Fatal("helper command is missing required arguments")
	}
	cfg := config.New()
	cfg.NoDatabase = true
	cfg.SwaggerURL = urlValue
	cfg.HeaderFile = headerPath
	cfg.OutputFormat = "json"
	if err := runAutomate(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
}

func commandLineValue(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

func captureCLIStreams(t *testing.T, run func() error) (string, string, error) {
	t.Helper()
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		t.Fatal(err)
	}
	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	defer func() { os.Stdout, os.Stderr = originalStdout, originalStderr }()

	runErr := run()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = originalStdout, originalStderr
	stdout, stdoutErr := io.ReadAll(stdoutReader)
	stderr, stderrErr := io.ReadAll(stderrReader)
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	if stdoutErr != nil || stderrErr != nil {
		t.Fatalf("read captured output: stdout=%v stderr=%v", stdoutErr, stderrErr)
	}
	return string(stdout), string(stderr), runErr
}

func assertDirectoryOmits(t *testing.T, root, forbidden string) {
	t.Helper()
	rootDirectory, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rootDirectory.Close() })
	if err := fs.WalkDir(rootDirectory.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		contents, err := rootDirectory.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(contents), forbidden) {
			return fmt.Errorf("%s contains private material", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func writeCLIPrivateHeaderFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.conf")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
