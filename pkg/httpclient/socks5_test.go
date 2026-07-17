package httpclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

type socksForwardFunc func(context.Context, string, string) (net.Conn, error)

func (fn socksForwardFunc) Dial(network, address string) (net.Conn, error) {
	return fn(context.Background(), network, address)
}

func (fn socksForwardFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return fn(ctx, network, address)
}

var _ proxy.ContextDialer = socksForwardFunc(nil)

func TestSOCKS5DialerRoutesAnonymousAndAuthenticatedConnections(t *testing.T) {
	for _, test := range []struct {
		name     string
		proxyURL string
		username string
		password string
	}{
		{name: "anonymous", proxyURL: "socks5://proxy.example"},
		{name: "username and password", proxyURL: "socks5h://proxy.example:1080", username: "audit-user", password: "correct horse battery staple"},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverResult := make(chan error, 1)
			forward := socksForwardFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "proxy.example:1080" {
					return nil, fmt.Errorf("proxy connection = %s %s", network, address)
				}
				clientConn, serverConn := net.Pipe()
				go func() {
					defer func() { _ = serverConn.Close() }()
					serverResult <- serveTestSOCKS5(serverConn, test.username, test.password, "api.internal:443")
				}()
				return clientConn, nil
			})

			dialer, err := newSOCKS5ContextDialer(test.proxyURL, test.username, test.password, forward)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", "api.internal:443")
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if err := <-serverResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSOCKS5DialerPropagatesAuthenticationRejectionWithoutCredentials(t *testing.T) {
	const username = "audit-user"
	const password = "do-not-log-this"
	serverResult := make(chan error, 1)
	forward := socksForwardFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			defer func() { _ = serverConn.Close() }()
			serverResult <- rejectTestSOCKS5Auth(serverConn)
		}()
		return clientConn, nil
	})
	dialer, err := newSOCKS5ContextDialer("socks5://proxy.example", username, password, forward)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialer.DialContext(context.Background(), "tcp", "api.internal:443")
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("error = %v, want authentication rejection", err)
	}
	if strings.Contains(err.Error(), username) || strings.Contains(err.Error(), password) {
		t.Fatalf("authentication error exposed credentials: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestSOCKS5DialerHonorsContextCancellation(t *testing.T) {
	forward := socksForwardFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	dialer, err := newSOCKS5ContextDialer("socks5://proxy.example:1080", "", "", forward)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = dialer.DialContext(ctx, "tcp", "api.internal:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestSOCKS5DialerRejectsUnsafeProxyURLs(t *testing.T) {
	forward := socksForwardFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	})
	for _, raw := range []string{
		"http://proxy.example:1080",
		"socks5://user:secret@proxy.example:1080",
		"socks5://proxy.example:1080/path",
		"socks5://proxy.example:1080?token=secret",
		"socks5://proxy.example:1080#fragment",
		"socks5://proxy.example:0",
		"socks5://proxy.example:65536",
		"socks5://",
	} {
		_, err := newSOCKS5ContextDialer(raw, "", "", forward)
		if err == nil {
			t.Errorf("accepted unsafe SOCKS5 URL %q", raw)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("error exposed proxy credentials: %v", err)
		}
	}
}

func rejectTestSOCKS5Auth(conn net.Conn) error {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if !slices.Contains(methods, byte(2)) {
		return fmt.Errorf("client did not offer username/password authentication")
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return err
	}
	var authHeader [2]byte
	if _, err := io.ReadFull(conn, authHeader[:]); err != nil {
		return err
	}
	username := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return err
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{1, 1}); err != nil {
		return err
	}
	return nil
}

func serveTestSOCKS5(conn net.Conn, username, password, wantTarget string) error {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if greeting[0] != 5 {
		return fmt.Errorf("greeting version = %d", greeting[0])
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}
	method := byte(0)
	if username != "" {
		method = 2
	}
	if !slices.Contains(methods, method) {
		return fmt.Errorf("methods = %v, want %d", methods, method)
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return fmt.Errorf("select auth method: %w", err)
	}
	if method == 2 {
		if err := verifyTestSOCKS5Auth(conn, username, password); err != nil {
			return err
		}
	}
	target, err := readTestSOCKS5Target(conn)
	if err != nil {
		return err
	}
	if target != wantTarget {
		return fmt.Errorf("target = %q, want %q", target, wantTarget)
	}
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		return fmt.Errorf("write connect response: %w", err)
	}
	return nil
}

func verifyTestSOCKS5Auth(conn net.Conn, username, password string) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}
	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	pass := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	if header[0] != 1 || string(user) != username || string(pass) != password {
		return fmt.Errorf("unexpected username/password authentication payload")
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return fmt.Errorf("write auth response: %w", err)
	}
	return nil
}

func readTestSOCKS5Target(conn net.Conn) (string, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", fmt.Errorf("read connect header: %w", err)
	}
	if header[0] != 5 || header[1] != 1 {
		return "", fmt.Errorf("unexpected connect header %v", header)
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", err
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = string(address)
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	default:
		return "", fmt.Errorf("unsupported address type %d", header[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:]))), nil
}
