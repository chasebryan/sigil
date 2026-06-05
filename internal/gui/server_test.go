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

func TestGUIIndexAndScriptStayInSync(t *testing.T) {
	s := &server{token: "test-token", mux: http.NewServeMux()}
	s.routes()
	handler := s.secureHeaders(s.mux)

	indexReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/", nil)
	indexResp := httptest.NewRecorder()
	handler.ServeHTTP(indexResp, indexReq)
	if indexResp.Code != http.StatusOK {
		t.Fatalf("index status = %d", indexResp.Code)
	}
	index := indexResp.Body.String()
	for _, needle := range []string{
		`id="copy-artifact"`,
		`id="copy-result"`,
		`id="save-result"`,
		`id="clear-result"`,
		`id="operation-form"`,
		`id="result-output"`,
	} {
		if !strings.Contains(index, needle) {
			t.Fatalf("index missing %s", needle)
		}
	}

	scriptReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/static/app.js", nil)
	scriptResp := httptest.NewRecorder()
	handler.ServeHTTP(scriptResp, scriptReq)
	if scriptResp.Code != http.StatusOK {
		t.Fatalf("script status = %d", scriptResp.Code)
	}
	script := scriptResp.Body.String()
	for _, needle := range []string{
		"function syncResultActions",
		"function copyPrimaryArtifact",
		"function refreshInputMeter",
		"function refreshTextMeter",
		"function formatBytes",
		"function timeStamp",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("script missing %s", needle)
		}
	}
}

func TestGUIProfileEndpoint(t *testing.T) {
	s := &server{token: "test-token", mux: http.NewServeMux()}
	s.routes()
	handler := s.secureHeaders(s.mux)

	body := bytes.NewBufferString(`{"data":"attack at dawn attack at dusk attack at dawn","encoding":"text","maxLag":32,"maxKeySize":40}`)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8765/api/profile", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sigil-Token", "test-token")
	req.Header.Set("Origin", "http://127.0.0.1:8765")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("profile API status = %d", resp.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["assessment"] != "small-sample triage" {
		t.Fatalf("unexpected profile assessment: %#v", result["assessment"])
	}
	if _, ok := result["bitStats"].(map[string]any); !ok {
		t.Fatalf("missing bitStats: %#v", result)
	}
}
