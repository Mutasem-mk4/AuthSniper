package requester

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ResponseData struct {
	StatusCode int
	Body       []byte
	Error      error
}

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{httpClient: client}
}

// ParseRawRequest reads a Burp-style raw HTTP request file and constructs a base http.Request
func ParseRawRequest(filePath string, https bool) (*http.Request, []byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, nil, err
	}

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	scheme := "http://"
	if https {
		scheme = "https://"
	}

	u, err := url.Parse(scheme + req.Host + req.RequestURI)
	if err != nil {
		return nil, nil, err
	}

	req.URL = u
	req.RequestURI = "" // MUST be empty for client requests

	return req, bodyBytes, nil
}

// CloneAndMutateRequest creates a copy of the base request and sets the auth token
func CloneAndMutateRequest(baseReq *http.Request, bodyBytes []byte, token string) *http.Request {
	req := baseReq.Clone(baseReq.Context())

	if len(bodyBytes) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	} else {
		req.Body = nil // Ensure we don't accidentally send garbage
	}

	if token != "" {
		if strings.HasPrefix(token, "Cookie: ") {
			req.Header.Set("Cookie", strings.TrimPrefix(token, "Cookie: "))
		} else {
			req.Header.Set("Authorization", token)
		}
	} else {
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
	}

	return req
}

func (c *Client) FireRequest(req *http.Request) ResponseData {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ResponseData{Error: err}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return ResponseData{Error: err, StatusCode: resp.StatusCode}
	}

	return ResponseData{
		StatusCode: resp.StatusCode,
		Body:       bodyBytes,
		Error:      nil,
	}
}

func (c *Client) Multiplex(baseReq *http.Request, bodyBytes []byte, tokenA, tokenB string) (ResponseData, ResponseData, ResponseData) {
	chA := make(chan ResponseData)
	chB := make(chan ResponseData)
	chU := make(chan ResponseData)

	go func() { chA <- c.FireRequest(CloneAndMutateRequest(baseReq, bodyBytes, tokenA)) }()
	go func() { chB <- c.FireRequest(CloneAndMutateRequest(baseReq, bodyBytes, tokenB)) }()
	go func() { chU <- c.FireRequest(CloneAndMutateRequest(baseReq, bodyBytes, "")) }()

	return <-chA, <-chB, <-chU
}
