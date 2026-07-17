package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/mr-pmillz/sj/pkg/config"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	HTTP   *http.Client
	Replay *http.Client
	Cfg    *config.Config

	depth    int
	surveyed bool
	avoidAll string
}

func NewClient(cfg *config.Config) *Client {
	transport := &http.Transport{}
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if cfg.Proxy != "NOPROXY" {
		proxyURL, _ := url.Parse(cfg.Proxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	c := &Client{HTTP: httpClient, Cfg: cfg}

	if cfg.ReplayProxy != "" {
		rt := &http.Transport{}
		if cfg.Insecure {
			rt.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		rpURL, err := url.Parse(cfg.ReplayProxy)
		if err != nil {
			fmt.Fprintf(io.Discard, "Error parsing replay proxy URL: %v", err)
			return c
		}
		rt.Proxy = http.ProxyURL(rpURL)
		c.Replay = &http.Client{
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return c
}

func (c *Client) userAgent() string {
	if c.Cfg.AgentExplicit {
		return c.Cfg.UserAgent
	}
	if c.Cfg.RandomUserAgent {
		return RandomUserAgent()
	}
	if c.Cfg.UserAgent != "" {
		return c.Cfg.UserAgent
	}
	return RandomUserAgent()
}

func (c *Client) applyHeaders(req *http.Request) (accept, contentType string) {
	for _, h := range c.Cfg.Headers {
		before, after, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		key := strings.TrimSpace(before)
		value := strings.TrimSpace(after)
		if key == "Accept" {
			accept = value
		}
		if key == "Content-Type" {
			contentType = value
		}
		req.Header.Set(key, value)
	}
	req.Header.Set("User-Agent", c.userAgent())
	return accept, contentType
}

func (c *Client) MakeRequest(method, target string, reqData io.Reader) ([]byte, string, int) {
	if c.Cfg.Quiet {
		c.avoidAll = "y"
	}

	u, err := url.Parse(target)
	if err != nil || u == nil {
		return nil, "", 0
	}

	endpoint := u.RawPath + "?" + u.RawQuery
	if c.Cfg.Mode == config.ModeAutomate && !c.Cfg.Force {
		for _, v := range DangerousStrings {
			if strings.Contains(endpoint, v) && !strings.Contains(strings.Join(c.Cfg.SafeWords, ","), v) {
				if c.Cfg.AcceptRisk {
					break
				}
				if c.avoidAll == "y" {
					return nil, "", 0
				}
				var userChoice string
				fmt.Fprintf(io.Discard, "Dangerous keyword '%s' detected in URL (%s).", v, target)
				if !c.Cfg.Quiet {
					fmt.Fprintf(io.Discard, " Skipping (use --force or --accept-risk).\n")
				}
				if strings.ToLower(userChoice) != "y" {
					if !c.surveyed {
						c.avoidAll = "y"
						c.surveyed = true
					}
					return nil, "", 0
				}
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, target, reqData)
	if err != nil {
		return nil, "", 0
	}

	accept, ct := c.applyHeaders(req)
	if accept == "" {
		req.Header.Set("Accept", "application/json, text/html, */*")
	}
	if method == "POST" && ct == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		if err == context.DeadlineExceeded {
			return nil, "", 0
		}
		errStr := fmt.Sprint(err)
		if (strings.Contains(errStr, "tls") || strings.Contains(errStr, "x509")) && !strings.Contains(errStr, "user canceled") {
			return nil, "tls_error", 0
		}
		if strings.Contains(errStr, "tcp") && strings.Contains(errStr, "no such host") {
			return nil, "no_such_host", 0
		}
		if strings.Contains(errStr, "user canceled") {
			return nil, "skipped", 1
		}
		return nil, "", 0
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	if (resp.StatusCode == 301 || resp.StatusCode == 302) && strings.Contains(bodyString, "<html>") && c.depth < 10 {
		c.depth++
		redirect, _ := resp.Location()
		if redirect != nil {
			result, rs, rsc := c.MakeRequest(method, redirect.Scheme+"://"+redirect.Host+redirect.Path, reqData)
			return result, rs, rsc
		}
	}

	c.depth = 0
	return bodyBytes, bodyString, resp.StatusCode
}

func (c *Client) CheckContentType(target string) string {
	ctx, cancel := context.WithTimeout(context.Background(), c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return ""
	}

	c.applyHeaders(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.Header.Get("Content-Type")
}

func (c *Client) ReplayRequest(method, target string, reqData io.Reader) {
	if c.Replay == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, target, reqData)
	if err != nil {
		return
	}

	c.applyHeaders(req)

	resp, err := c.Replay.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	fmt.Fprintf(io.Discard, "[Replay] %s %s -> %d\n", method, target, resp.StatusCode)
}

func (c *Client) BruteFetch(target string) ([]byte, string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, "", 0
	}

	c.applyHeaders(req)
	req.Header.Set("Accept", "application/json, application/yaml, text/html, */*")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", 0
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, resp.Header.Get("Content-Type"), resp.StatusCode
	}

	return bodyBytes, resp.Header.Get("Content-Type"), resp.StatusCode
}

var DangerousStrings = []string{
	"add", "block", "build", "buy", "change", "clear", "create", "delete",
	"deploy", "destroy", "drop", "edit", "emergency", "erase", "execute",
	"insert", "modify", "order", "overwrite", "pause", "purchase", "rebuild",
	"remove", "replace", "reset", "restart", "revoke", "run", "sell", "send",
	"set", "start", "stop", "update", "upload", "write",
}
