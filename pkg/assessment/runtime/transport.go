package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"

	"github.com/mr-pmillz/sj/pkg/assessment/executor"
	xproxy "golang.org/x/net/proxy"
)

type networkProxyVerifier struct{ address string }

func (verifier networkProxyVerifier) Verify(ctx context.Context) error {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", verifier.address)
	if err != nil {
		return err
	}
	return connection.Close()
}

func clientForProof(base *http.Client, proof persistedNode, configuredSOCKS *configuredSOCKSTransport) (*http.Client, executor.ProxyVerifier, error) {
	client := *base
	if !proof.ProxyRequired && !proof.InsecureTLS {
		return &client, nil, nil
	}
	var transport *http.Transport
	switch configured := base.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, nil, errors.New("assessment transport policy requires an HTTP transport that can be safely cloned")
	}
	if proof.InsecureTLS {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		// #nosec G402 -- manifest validation requires an explicit justification for this opt-in.
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	if !proof.ProxyRequired {
		client.Transport = transport
		return &client, nil, nil
	}
	proxyURL, err := url.Parse(proof.ProxyURL)
	if err != nil || proxyURL.Hostname() == "" {
		return nil, nil, executor.ErrProxyUnavailable
	}
	address := proxyURL.Host
	switch proxyURL.Scheme {
	case "http":
		if proxyURL.Port() == "" {
			address = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	case "https":
		if proxyURL.Port() == "" {
			address = net.JoinHostPort(proxyURL.Hostname(), "443")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5", "socks5h":
		if proxyURL.Port() == "" {
			address = net.JoinHostPort(proxyURL.Hostname(), "1080")
		}
		canonicalProxyURL, canonicalErr := canonicalSOCKSProxyURL(proof.ProxyURL)
		if canonicalErr != nil {
			return nil, nil, executor.ErrProxyUnavailable
		}
		if configuredSOCKS != nil && configuredSOCKS.proxyURL == canonicalProxyURL {
			transport.DialContext = classifySOCKSTargetDialErrors(configuredSOCKS.dialContext)
		} else {
			dialer, dialErr := xproxy.SOCKS5("tcp", address, nil, &net.Dialer{})
			if dialErr != nil {
				return nil, nil, fmt.Errorf("configure required SOCKS proxy: %w", dialErr)
			}
			contextDialer, ok := dialer.(xproxy.ContextDialer)
			if !ok {
				return nil, nil, executor.ErrProxyUnavailable
			}
			transport.DialContext = classifySOCKSTargetDialErrors(contextDialer.DialContext)
		}
		transport.Proxy = nil
		transport.DialTLSContext = nil
		transport.DialTLS = nil //nolint:staticcheck // Clear the deprecated hook to prevent mandatory SOCKS bypass.
	default:
		return nil, nil, executor.ErrProxyUnavailable
	}
	client.Transport = transport
	return &client, networkProxyVerifier{address: address}, nil
}

func classifySOCKSTargetDialErrors(
	dialContext func(context.Context, string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dialContext(ctx, network, address)
		if err != nil && isSOCKSTargetDialError(err) {
			return nil, errors.Join(err, ErrTargetOriginTransport)
		}
		return connection, err
	}
}

func isSOCKSTargetDialError(err error) bool {
	var operation *net.OpError
	if !errors.As(err, &operation) ||
		!strings.HasPrefix(strings.ToLower(operation.Op), "socks ") || operation.Err == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(operation.Err.Error())) {
	case "network unreachable", "host unreachable", "connection refused", "ttl expired":
		return true
	default:
		return false
	}
}

func isDirectTargetDialError(err error) bool {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

func canonicalSOCKSProxyURL(raw string) (string, error) {
	proxyURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || proxyURL.Hostname() == "" || proxyURL.Opaque != "" ||
		proxyURL.User != nil || proxyURL.RawQuery != "" || proxyURL.Fragment != "" ||
		(proxyURL.Path != "" && proxyURL.Path != "/") {
		return "", errors.New("SOCKS proxy must be an absolute credential-free URL without a path, query, or fragment")
	}
	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme != "socks5" && scheme != "socks5h" {
		return "", errors.New("SOCKS proxy must use socks5 or socks5h")
	}
	port := proxyURL.Port()
	if port == "" {
		port = "1080"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("SOCKS proxy must contain a valid TCP port")
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(proxyURL.Hostname()), port), nil
}
