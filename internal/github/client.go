// Package github collects a Wardmap snapshot from the GitHub REST API using a
// read-only token. It only issues GET requests and never reads secret values
// (GitHub does not expose them).
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Client is a minimal GitHub REST client.
type Client struct {
	BaseURL   string
	Token     string
	HTTP      *http.Client
	UserAgent string
	// MaxWait caps how long the client sleeps for a rate-limit reset.
	MaxWait time.Duration
}

// StatusError is returned for non-2xx responses.
type StatusError struct {
	Code int
	URL  string
	Msg  string
}

func (e *StatusError) Error() string { return fmt.Sprintf("GET %s: %d %s", e.URL, e.Code, e.Msg) }

// IsAccessDenied reports whether err is a 401/403/404 (GitHub returns 404 for
// resources the token cannot see).
func IsAccessDenied(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Code == 401 || se.Code == 403 || se.Code == 404)
}

var nextLinkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Get fetches path (relative to BaseURL, or absolute) into v and returns the
// next-page URL, if any.
func (c *Client) Get(ctx context.Context, path string, v any) (string, error) {
	u := path
	if !strings.HasPrefix(path, "http") {
		u = strings.TrimSuffix(c.BaseURL, "/") + path
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", c.UserAgent)
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if attempt < 3 {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			return "", err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		if wait, ok := c.rateLimitWait(resp); ok && attempt < 3 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return "", ctx.Err()
			}
			continue
		}
		if resp.StatusCode >= 500 && attempt < 3 {
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			var m struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(body, &m)
			return "", &StatusError{Code: resp.StatusCode, URL: redact(u), Msg: m.Message}
		}
		if v != nil {
			if err := json.Unmarshal(body, v); err != nil {
				return "", fmt.Errorf("decode %s: %w", redact(u), err)
			}
		}
		next := ""
		if m := nextLinkRe.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			next = m[1]
		}
		return next, nil
	}
}

func (c *Client) rateLimitWait(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != 403 && resp.StatusCode != 429 {
		return 0, false
	}
	max := c.MaxWait
	if max == 0 {
		max = 5 * time.Minute
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if s, err := strconv.Atoi(ra); err == nil {
			return min(time.Duration(s)*time.Second, max), true
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if s, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return min(time.Until(time.Unix(s, 0))+time.Second, max), true
		}
	}
	return 0, false
}

func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	p.User = nil
	return p.String()
}
