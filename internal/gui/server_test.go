package gui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGUIHeadersAndTokenGuard(t *testing.T) {
	s := &server{token: "test-token", mux: http.NewServeMux()}
	s.routes()
	handler := s.secureHeaders(s.mux)

	indexReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/", nil)
	indexResp := httptest.NewRecorder()
	handler.ServeHTTP(indexResp, indexReq)
	if indexResp.Code != http.StatusOK {
		t.Fatalf("index status = %d", indexResp.Code)
	}
	csp := indexResp.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("unexpected CSP: %q", csp)
	}

	payload := bytes.NewBufferString(`{"data":"abc","encoding":"text","algorithm":"sha256"}`)
	unauthorizedReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8765/api/digest", payload)
	unauthorizedReq.Header.Set("Content-Type", "application/json")
	unauthorizedResp := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResp, unauthorizedReq)
	if unauthorizedResp.Code != http.StatusForbidden {
		t.Fatalf("unguarded API status = %d", unauthorizedResp.Code)
	}

	body := bytes.NewBufferString(`{"data":"abc","encoding":"text","algorithm":"sha256"}`)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8765/api/digest", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sigil-Token", "test-token")
	req.Header.Set("Origin", "http://127.0.0.1:8765")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, req)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized API status = %d", authorized.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(authorized.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["hex"] != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("unexpected digest result: %#v", result)
	}
}
