package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"qxss/internal/config"
)

const (
	canaryBytes = 8
)

var Chars = []string{
	`<`, `>`, `"`, `'`, `{`, `}`, `(`, `)`, `[`, `]`, `\`, `/`, `;`, "`", `-`,
}

var ErrParamNotFound = errors.New("query parameter not found")

type Scanner struct {
	client	*http.Client
	limiter	*rate.Limiter
}

func New(rps float64, burst int) *Scanner {
	return &Scanner{
		client: &http.Client{Timeout: 10 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
}

func canary() (string, error) {
	bytes := make([]byte, canaryBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate canary: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

func (s *Scanner) probe(ctx context.Context, target string) (string, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return "", fmt.Errorf("wait rate limit: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting url: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	return string(body), nil
}

func (s *Scanner) Params(ctx context.Context, rawURL string) (config.Reflected, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return config.Reflected{}, fmt.Errorf("parsing url: %w", err)
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return config.Reflected{}, fmt.Errorf("parse query of %q: %w", rawURL, err)
	}

	var keys []string

	for key := range query {
		q := url.Values{}
		for k, v := range query {
			q[k] = append([]string(nil), v...)
		}

		c, err := canary()
		if err != nil {
			return config.Reflected{}, err
		}

		q.Set(key, c)
		u.RawQuery = q.Encode()

		body, err := s.probe(ctx, u.String())
		if err != nil {
			return config.Reflected{}, err
		}

		if strings.Contains(body, c) {
			keys = append(keys, key)
		}
	}

	return config.Reflected{URL: rawURL, Params: keys}, nil
}

func (s *Scanner) FuzzChars(ctx context.Context, rawURL, param string) (config.ResultChars, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return config.ResultChars{}, fmt.Errorf("parsing url: %w", err)
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return config.ResultChars{}, fmt.Errorf("parse query of %q: %w", rawURL, err)
	}

	values, ok := query[param]
	if !ok {
		return config.ResultChars{}, fmt.Errorf("%w: %q in %q", ErrParamNotFound, param, rawURL)
	}

	c, err := canary()
	if err != nil {
		return config.ResultChars{}, err
	}

	var allowed []string
	for _, char := range Chars {
		craft := c + char
		values[0] = craft
		query[param] = values
		u.RawQuery = query.Encode()

		body, err := s.probe(ctx, u.String())
		if err != nil {
			return config.ResultChars{}, err
		}

		if strings.Contains(body, craft) {
			allowed = append(allowed, char)
		}
	}

	return config.ResultChars{URL: rawURL, Param: param, Chars: allowed}, nil
}

func (s *Scanner) FuzzPayloads(ctx context.Context, rawURL, param string, payloads []string) (config.ResultPayloads, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return config.ResultPayloads{}, fmt.Errorf("parsing url: %w", err)
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return config.ResultPayloads{}, fmt.Errorf("parsing query of %q: %w", rawURL, err)
	}

	values, ok := query[param]
	if !ok {
		return config.ResultPayloads{}, fmt.Errorf("%w: %q in %q", ErrParamNotFound, param, rawURL)
	}

	c, err := canary()
	if err != nil {
		return config.ResultPayloads{}, err
	}

	var success []string
	for _, p := range payloads {
		craft := c + p
		values[0] = craft
		query[param] = values
		u.RawQuery = query.Encode()

		body, err := s.probe(ctx, u.String())
		if err != nil {
			return config.ResultPayloads{}, err
		}

		if strings.Contains(body, craft) {
			success = append(success, p)
		}
	}

	return config.ResultPayloads{URL: rawURL, Param: param, Payloads: success}, nil
	
}
