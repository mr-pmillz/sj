package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	"github.com/mr-pmillz/sj/pkg/assessment/inventory"
	"github.com/mr-pmillz/sj/pkg/assessment/model"
	"github.com/mr-pmillz/sj/pkg/assessment/planner"
	"github.com/mr-pmillz/sj/pkg/assessment/reference"
	"github.com/mr-pmillz/sj/pkg/store"
)

type fixedRoundTripper struct{}

func (fixedRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not used")
}

func TestClientForProofEnforcesManifestTransportVariants(t *testing.T) {
	base := &http.Client{}
	plain, verifier, err := clientForProof(base, persistedNode{}, nil)
	if err != nil || plain == base || verifier != nil {
		t.Fatalf("plain client=%p verifier=%v error=%v", plain, verifier, err)
	}

	insecure, verifier, err := clientForProof(base, persistedNode{InsecureTLS: true}, nil)
	if err != nil || verifier != nil {
		t.Fatal(err)
	}
	transport := insecure.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("manifest insecure TLS policy was not installed")
	}
	originalTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	cloned, _, err := clientForProof(&http.Client{Transport: &http.Transport{TLSClientConfig: originalTLS}}, persistedNode{InsecureTLS: true}, nil)
	if err != nil || cloned.Transport.(*http.Transport).TLSClientConfig == originalTLS {
		t.Fatal("TLS configuration was not safely cloned")
	}

	if _, _, err := clientForProof(&http.Client{Transport: fixedRoundTripper{}}, persistedNode{InsecureTLS: true}, nil); err == nil {
		t.Fatal("custom transport accepted for manifest TLS mutation")
	}

	tests := []struct {
		name      string
		proxyURL  string
		wantProxy bool
		wantError bool
	}{
		{name: "HTTP", proxyURL: "http://127.0.0.1:8080", wantProxy: true},
		{name: "HTTPS default port", proxyURL: "https://proxy.example", wantProxy: true},
		{name: "SOCKS default port", proxyURL: "socks5h://127.0.0.1"},
		{name: "invalid", proxyURL: "ftp://127.0.0.1", wantError: true},
		{name: "missing", proxyURL: "", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, verifier, err := clientForProof(base, persistedNode{ProxyRequired: true, ProxyURL: test.proxyURL}, nil)
			if test.wantError {
				if err == nil {
					t.Fatal("required proxy policy unexpectedly succeeded")
				}
				return
			}
			if err != nil || verifier == nil {
				t.Fatalf("client=%v verifier=%v error=%v", client, verifier, err)
			}
			configured := client.Transport.(*http.Transport)
			if test.wantProxy && configured.Proxy == nil {
				t.Fatal("HTTP proxy function is missing")
			}
			if !test.wantProxy && configured.Proxy != nil {
				t.Fatal("SOCKS transport retained HTTP proxy routing")
			}
		})
	}
}

func TestClientForProofPreservesMatchingConfiguredSOCKSAuthentication(t *testing.T) {
	authRejected := errors.New("configured SOCKS authentication rejected")
	dialCalls := 0
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dialCalls++
		return nil, authRejected
	}
	service, err := New(Config{
		Client:      http.DefaultClient,
		EvidenceKey: make([]byte, 32),
		SOCKSTransport: &SOCKSTransportConfig{
			ProxyURL:    "socks5h://LOCALHOST",
			DialContext: transport.DialContext,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, verifier, err := clientForProof(
		service.client,
		persistedNode{ProxyRequired: true, ProxyURL: "socks5h://localhost:1080"},
		service.socksTransport,
	)
	if err != nil || verifier == nil {
		t.Fatalf("client=%v verifier=%v error=%v", client, verifier, err)
	}
	configured := client.Transport.(*http.Transport)
	_, dialErr := configured.DialContext(t.Context(), "tcp", "api.internal:443")
	if !errors.Is(dialErr, authRejected) || dialCalls != 1 {
		t.Fatalf("dial error=%v calls=%d, want configured authentication failure", dialErr, dialCalls)
	}
}

func TestSOCKSTargetDialErrorClassificationIsConservative(t *testing.T) {
	proxyAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	targetAddress := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "target refused",
			err: &net.OpError{
				Op: "socks connect", Net: "tcp", Source: proxyAddress,
				Addr: targetAddress, Err: errors.New("connection refused"),
			},
			want: true,
		},
		{
			name: "target host unreachable",
			err: &net.OpError{
				Op: "socks connect", Net: "tcp", Source: proxyAddress,
				Addr: targetAddress, Err: errors.New("host unreachable"),
			},
			want: true,
		},
		{
			name: "handshake EOF",
			err: &net.OpError{
				Op: "socks connect", Net: "tcp", Source: proxyAddress,
				Addr: targetAddress, Err: io.EOF,
			},
		},
		{name: "direct refusal", err: &net.OpError{Op: "dial", Net: "tcp", Addr: targetAddress, Err: errors.New("connection refused")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isSOCKSTargetDialError(test.err); got != test.want {
				t.Fatalf("classification = %t, want %t", got, test.want)
			}
		})
	}
}

func TestClientForProofRequiredSOCKSNeverFallsBackToDirectDial(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	directConnection := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := target.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			directConnection <- struct{}{}
		}
	}()

	unavailableProxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := unavailableProxy.Addr().String()
	if err := unavailableProxy.Close(); err != nil {
		t.Fatal(err)
	}
	directDialCalls := 0
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		directDialCalls++
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	client, _, err := clientForProof(
		&http.Client{Transport: baseTransport},
		persistedNode{ProxyRequired: true, ProxyURL: "socks5h://" + proxyAddress},
		&configuredSOCKSTransport{
			proxyURL:    "socks5h://127.0.0.1:1",
			dialContext: baseTransport.DialContext,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	configured := client.Transport.(*http.Transport)
	dialCtx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	if connection, dialErr := configured.DialContext(dialCtx, "tcp", target.Addr().String()); dialErr == nil {
		_ = connection.Close()
		t.Fatal("required SOCKS transport dialed the target without its proxy")
	}
	select {
	case <-directConnection:
		t.Fatal("required SOCKS transport fell back to a direct target connection")
	case <-time.After(50 * time.Millisecond):
	}
	if directDialCalls != 0 {
		t.Fatalf("required SOCKS transport invoked a custom direct dialer %d time(s)", directDialCalls)
	}
}

func TestClientForProofRequiredSOCKSClearsDirectTLSDialers(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*http.Transport, *int)
	}{{
		name: "DialTLSContext",
		configure: func(transport *http.Transport, calls *int) {
			transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				*calls++
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
		},
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = target.Close() }()
			directConnection := make(chan struct{}, 1)
			go func() {
				connection, acceptErr := target.Accept()
				if acceptErr == nil {
					_ = connection.Close()
					directConnection <- struct{}{}
				}
			}()

			unavailableProxy, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			proxyAddress := unavailableProxy.Addr().String()
			if err := unavailableProxy.Close(); err != nil {
				t.Fatal(err)
			}
			baseTransport := http.DefaultTransport.(*http.Transport).Clone()
			dialCalls := 0
			test.configure(baseTransport, &dialCalls)
			client, _, err := clientForProof(
				&http.Client{Transport: baseTransport},
				persistedNode{ProxyRequired: true, ProxyURL: "socks5h://" + proxyAddress},
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			requestCtx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			request, err := http.NewRequestWithContext(
				requestCtx, http.MethodGet, "https://"+target.Addr().String(), nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			response, requestErr := client.Do(request)
			if response != nil {
				_ = response.Body.Close()
			}
			if requestErr == nil {
				t.Fatal("required SOCKS HTTPS request unexpectedly succeeded")
			}
			select {
			case <-directConnection:
				t.Fatal("required SOCKS HTTPS request used a direct TLS dialer")
			case <-time.After(50 * time.Millisecond):
			}
			if dialCalls != 0 {
				t.Fatalf("required SOCKS HTTPS request invoked direct TLS dialer %d time(s)", dialCalls)
			}
		})
	}
}

func TestLocalInputReaderRejectsUnsafeAndOversizedFiles(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "input.json")
	if err := os.WriteFile(regular, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(regular, 4); err == nil {
		t.Fatal("oversized input was accepted")
	}
	symlink := filepath.Join(directory, "link.json")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(symlink, 10); err == nil {
		t.Fatal("symlink input was accepted")
	}
	if _, err := readRegularBounded(filepath.Join(directory, "missing"), 10); err == nil {
		t.Fatal("missing input was accepted")
	}
}

func TestStoredRunDatasetAndSelectionHelpers(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "results.db")
	resultStore, err := store.Open(t.Context(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resultStore.BeginRun(t.Context(), "automate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resultStore.AddObservations(t.Context(), run.ID, []store.Observation{{
		Kind: "automate", Source: "fixture", Method: http.MethodGet,
		URL: "https://api.example.test/items/101", Path: "/items/101", Status: 200,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := resultStore.Close(); err != nil {
		t.Fatal(err)
	}
	dataset, err := loadStoredDataset(t.Context(), databasePath, false, run.ID)
	if err != nil || len(dataset.Operations) != 1 {
		t.Fatalf("dataset operations=%d error=%v", len(dataset.Operations), err)
	}
	if _, err := loadStoredDataset(t.Context(), "", true, run.ID); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("no-database error = %v", err)
	}

	operations := []inventory.Operation{{ID: "one", OperationID: "getOne"}, {ID: "two", OperationID: "getTwo"}}
	all := model.NewInputSource("all", model.InputKindOpenAPI, "/tmp/spec", "", "", "", nil, nil)
	if selected := selectOperations(operations, all); len(selected) != 2 {
		t.Fatalf("unfiltered operations = %d", len(selected))
	}
	filtered := model.NewInputSource("filtered", model.InputKindOpenAPI, "/tmp/spec", "", "", "", []string{"getTwo"}, nil)
	if selected := selectOperations(operations, filtered); len(selected) != 1 || selected[0].ID != "two" {
		t.Fatalf("filtered operations = %#v", selected)
	}
}

func TestReferenceMutationAndSentinelHelpers(t *testing.T) {
	value := any(map[string]any{"items": []any{map[string]any{"itemId": "101"}}})
	if !setJSONPointer(value, "/items/0/itemId", "202") {
		t.Fatal("nested array pointer was not updated")
	}
	if setJSONPointer(value, "/items/nope/itemId", "202") || setJSONPointer("scalar", "/x", "202") {
		t.Fatal("invalid JSON pointer was accepted")
	}
	for _, kind := range []reference.Kind{
		reference.KindNumeric, reference.KindUUID, reference.KindULID,
		reference.KindObjectID, reference.KindBase64, reference.KindSlug,
	} {
		if nonexistentIdentifier(kind) == "" {
			t.Fatalf("empty sentinel for %s", kind)
		}
	}
	if _, ok := materializeSchema(map[string]any{"items": map[string]any{"default": "101"}}, "items", nil, 0); !ok {
		t.Fatal("array schema default was not materialized")
	}
	if _, ok := materializeSchema(nil, "itemId", nil, 33); ok {
		t.Fatal("over-depth schema was materialized")
	}
	if errorsNoOperations() == nil || safeError(nil) != "" || originOnly("://bad") != "" {
		t.Fatal("error and URL helper invariants failed")
	}
}

func TestNewRequiresEvidenceKeyAndDefaultsClientAndClock(t *testing.T) {
	if _, err := New(Config{EvidenceKey: []byte("short")}); err == nil {
		t.Fatal("short evidence key accepted")
	}
	dialContext := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("not dialed")
	}
	for _, socksTransport := range []*SOCKSTransportConfig{
		{ProxyURL: "http://proxy.example", DialContext: dialContext},
		{ProxyURL: "socks5://user:password@proxy.example", DialContext: dialContext},
		{ProxyURL: "socks5://proxy.example"},
	} {
		if _, err := New(Config{EvidenceKey: make([]byte, 32), SOCKSTransport: socksTransport}); err == nil {
			t.Fatalf("invalid configured SOCKS transport %#v was accepted", socksTransport)
		}
	}
	service, err := New(Config{EvidenceKey: make([]byte, 32)})
	if err != nil || service.client == nil || service.now == nil {
		t.Fatalf("default service=%#v error=%v", service, err)
	}
	if _, err := service.Status(context.Background(), StatusRequest{NoDatabase: true}); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("status no-database error = %v", err)
	}
}

func TestDirectTargetFailureIsolationRequiresDeclaredDirectTransport(t *testing.T) {
	failure := errors.Join(executor.ErrTransport, syscall.ECONNREFUSED)
	attempt := executor.Attempt{Outcome: executor.OutcomeRetryableNoSideEffect}
	if isIsolatedTargetTransportFailure(failure, attempt, false, false) {
		t.Fatal("ambiguous custom transport failure was isolated as target-local")
	}
	if !isIsolatedTargetTransportFailure(failure, attempt, false, true) {
		t.Fatal("declared direct connection refusal was not isolated")
	}
}

func TestBudgetLimitsRejectsNegativeByteLimits(t *testing.T) {
	_, err := budgetLimits(model.NewBudgetLimit(1, -1, 2, 1))
	if err == nil {
		t.Fatal("negative request-byte limit wrapped into a valid planner budget")
	}
}

func TestBudgetLimitsRejectsInvalidRequestRates(t *testing.T) {
	for _, requestsPerSecond := range []float64{0, -1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := budgetLimits(model.NewBudgetLimit(1, 1, 1, requestsPerSecond)); err == nil {
			t.Fatalf("invalid request rate %v was accepted", requestsPerSecond)
		}
	}
}

func TestProofCaseCostChecksConversionAndArithmeticBounds(t *testing.T) {
	tests := []struct {
		name string
		node persistedNode
	}{
		{name: "negative redirects", node: persistedNode{MaxRedirects: -1, MaxRequestBytes: 1, MaxResponseBytes: 1}},
		{name: "negative request bytes", node: persistedNode{MaxRequestBytes: -1, MaxResponseBytes: 1}},
		{name: "negative response bytes", node: persistedNode{MaxRequestBytes: 1, MaxResponseBytes: -1}},
		{name: "redirect byte multiplication overflow", node: persistedNode{
			MaxRedirects: 1, MaxRequestBytes: math.MaxInt64, MaxResponseBytes: math.MaxInt64,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := proofCaseCost(test.node); err == nil {
				t.Fatal("invalid proof cost was accepted")
			}
		})
	}

	cost, err := proofCaseCost(persistedNode{MaxRedirects: 2, MaxRequestBytes: 10, MaxResponseBytes: 20})
	if err != nil || cost.Requests != 3 || cost.Bytes != 90 {
		t.Fatalf("valid proof cost = %#v, error = %v", cost, err)
	}
	if _, err := multiplyCost(cost, math.MaxUint64); err == nil {
		t.Fatal("overflowing proof matrix cost was accepted")
	}
}

func TestExecutionSnapshotRejectsCostsOutsideDurableBounds(t *testing.T) {
	prepared := preparedPlan{
		plan: planner.Plan{Nodes: []planner.Node{{
			ID: "oversized", Cost: planner.Cost{Requests: math.MaxUint64, Bytes: 1},
		}}},
		proofs: map[string]persistedNode{"oversized": {}},
	}
	if _, err := executionSnapshotFromPrepared(prepared); err == nil {
		t.Fatal("unsigned planner cost outside durable bounds entered the execution snapshot")
	}
}

func TestExecutionSnapshotCanonicalizesEmptyCollections(t *testing.T) {
	snapshot, err := executionSnapshotFromPrepared(preparedPlan{
		plan:   planner.Plan{Hash: "inventory-only"},
		proofs: map[string]persistedNode{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Identities == nil || snapshot.Nodes == nil {
		t.Fatalf("empty signed collections must encode as arrays: identities=%#v nodes=%#v", snapshot.Identities, snapshot.Nodes)
	}
}
