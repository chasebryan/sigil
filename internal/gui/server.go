package gui

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	sigilcrypto "github.com/chasebryan/sigil/internal/crypto"
)

const maxAPIBody = 24 << 20

//go:embed static/*
var staticFiles embed.FS

type Config struct {
	Addr   string
	Stdout io.Writer
}

type server struct {
	token string
	mux   *http.ServeMux
}

func Serve(cfg Config) error {
	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:8765"
	}
	stdout := cfg.Stdout
	if stdout == nil {
		stdout = io.Discard
	}

	token, err := sessionToken()
	if err != nil {
		return err
	}
	s := &server{token: token, mux: http.NewServeMux()}
	s.routes()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	fmt.Fprintf(stdout, "Sigil GUI running at http://%s\n", listener.Addr().String())
	fmt.Fprintln(stdout, "Processing is local to this Sigil process. Press Ctrl+C to stop.")

	httpServer := &http.Server{
		Handler:           s.secureHeaders(s.mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return httpServer.Serve(listener)
}

func (s *server) routes() {
	s.mux.HandleFunc("/", s.index)
	s.mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))
	s.mux.HandleFunc("/api/algorithms", s.api(s.algorithms))
	s.mux.HandleFunc("/api/digest", s.api(s.digest))
	s.mux.HandleFunc("/api/hmac", s.api(s.hmac))
	s.mux.HandleFunc("/api/entropy", s.api(s.entropy))
	s.mux.HandleFunc("/api/random", s.api(s.random))
	s.mux.HandleFunc("/api/xor", s.api(s.xor))
	s.mux.HandleFunc("/api/keygen", s.api(s.keygen))
	s.mux.HandleFunc("/api/sign", s.api(s.sign))
	s.mux.HandleFunc("/api/verify", s.api(s.verify))
	s.mux.HandleFunc("/api/seal", s.api(s.seal))
	s.mux.HandleFunc("/api/open", s.api(s.open))
}

func (s *server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), clipboard-read=(), clipboard-write=(self)")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTemplate.Execute(w, map[string]string{"Token": s.token}); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

func (s *server) api(handler func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.validRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := handler(w, r); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		}
	}
}

func (s *server) validRequest(r *http.Request) bool {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Sigil-Token")), []byte(s.token)) != 1 {
		return false
	}
	if fetchSite := r.Header.Get("Sec-Fetch-Site"); fetchSite != "" && fetchSite != "same-origin" && fetchSite != "none" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || !sameHost(parsed.Host, r.Host) {
			return false
		}
	}
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "application/json")
}

func sameHost(left, right string) bool {
	return strings.EqualFold(left, right)
}

func (s *server) algorithms(w http.ResponseWriter, _ *http.Request) error {
	return encode(w, map[string]any{
		"hashes": sigilcrypto.AvailableHashAlgorithms(),
		"seal": map[string]any{
			"algorithm":  "AES-256-GCM",
			"kdf":        "PBKDF2-HMAC-SHA256",
			"iterations": sigilcrypto.DefaultPBKDF2Iterations,
		},
		"signatures": []string{"Ed25519"},
	})
}

func (s *server) digest(w http.ResponseWriter, r *http.Request) error {
	var req dataRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	data, err := sigilcrypto.DecodeInput(req.Data, req.Encoding)
	if err != nil {
		return err
	}
	result, err := sigilcrypto.DigestBytes(data, req.Algorithm)
	if err != nil {
		return err
	}
	return encode(w, result)
}

func (s *server) hmac(w http.ResponseWriter, r *http.Request) error {
	var req macRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	data, err := sigilcrypto.DecodeInput(req.Data, req.Encoding)
	if err != nil {
		return err
	}
	key, err := sigilcrypto.DecodeInput(req.Key, req.KeyEncoding)
	if err != nil {
		return err
	}
	result, err := sigilcrypto.HMACBytes(data, key, req.Algorithm)
	if err != nil {
		return err
	}
	return encode(w, result)
}

func (s *server) entropy(w http.ResponseWriter, r *http.Request) error {
	var req dataRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	data, err := sigilcrypto.DecodeInput(req.Data, req.Encoding)
	if err != nil {
		return err
	}
	return encode(w, sigilcrypto.AnalyzeBytes(data))
}

func (s *server) random(w http.ResponseWriter, r *http.Request) error {
	var req randomRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Kind == "password" {
		password, err := sigilcrypto.RandomPassword(req.Size)
		if err != nil {
			return err
		}
		return encode(w, map[string]any{
			"kind":     "password",
			"password": password,
			"length":   len(password),
		})
	}
	random, err := sigilcrypto.RandomBytes(req.Size)
	if err != nil {
		return err
	}
	output := req.Output
	if output == "" {
		output = "hex"
	}
	encoded, err := sigilcrypto.EncodeOutput(random, output)
	if err != nil {
		return err
	}
	return encode(w, map[string]any{
		"kind":     "bytes",
		"encoding": output,
		"size":     len(random),
		"value":    encoded,
		"entropy":  sigilcrypto.AnalyzeBytes(random),
	})
}

func (s *server) xor(w http.ResponseWriter, r *http.Request) error {
	var req xorRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	left, err := sigilcrypto.DecodeInput(req.Left, req.Encoding)
	if err != nil {
		return err
	}
	right, err := sigilcrypto.DecodeInput(req.Right, req.Encoding)
	if err != nil {
		return err
	}
	var out []byte
	switch strings.ToLower(req.Mode) {
	case "", "fixed":
		out, err = sigilcrypto.FixedXOR(left, right)
	case "repeating":
		out, err = sigilcrypto.RepeatingXOR(left, right)
	default:
		return fmt.Errorf("unknown XOR mode %q", req.Mode)
	}
	if err != nil {
		return err
	}
	output := req.Output
	if output == "" {
		output = "hex"
	}
	encoded, err := sigilcrypto.EncodeOutput(out, output)
	if err != nil {
		return err
	}
	return encode(w, map[string]any{"encoding": output, "value": encoded, "size": len(out)})
}

func (s *server) keygen(w http.ResponseWriter, _ *http.Request) error {
	pair, err := sigilcrypto.GenerateEd25519KeyPair()
	if err != nil {
		return err
	}
	return encode(w, pair)
}

func (s *server) sign(w http.ResponseWriter, r *http.Request) error {
	var req signRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	data, err := sigilcrypto.DecodeInput(req.Data, req.Encoding)
	if err != nil {
		return err
	}
	signature, err := sigilcrypto.SignBytes(req.PrivatePEM, data)
	if err != nil {
		return err
	}
	return encode(w, map[string]any{
		"algorithm": "Ed25519",
		"signature": signature,
		"size":      len(data),
	})
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) error {
	var req verifyRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	data, err := sigilcrypto.DecodeInput(req.Data, req.Encoding)
	if err != nil {
		return err
	}
	ok, err := sigilcrypto.VerifyBytes(req.PublicPEM, req.Signature, data)
	if err != nil {
		return err
	}
	return encode(w, map[string]any{"algorithm": "Ed25519", "valid": ok, "size": len(data)})
}

func (s *server) seal(w http.ResponseWriter, r *http.Request) error {
	var req sealRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	data, err := sigilcrypto.DecodeInput(req.Data, req.Encoding)
	if err != nil {
		return err
	}
	iterations := req.Iterations
	if iterations == 0 {
		iterations = sigilcrypto.DefaultPBKDF2Iterations
	}
	var sealed bytes.Buffer
	info, err := sigilcrypto.Seal(&sealed, bytes.NewReader(data), sigilcrypto.SealOptions{
		Passphrase: req.Passphrase,
		Iterations: iterations,
	})
	if err != nil {
		return err
	}
	return encode(w, map[string]any{
		"sealedBase64": base64.StdEncoding.EncodeToString(sealed.Bytes()),
		"info":         info,
		"inputSize":    len(data),
		"sealedSize":   sealed.Len(),
	})
}

func (s *server) open(w http.ResponseWriter, r *http.Request) error {
	var req openRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.SealedBase64))
	if err != nil {
		return fmt.Errorf("decode sealed base64: %w", err)
	}
	var plain bytes.Buffer
	info, err := sigilcrypto.Open(&plain, bytes.NewReader(sealed), req.Passphrase)
	if err != nil {
		return err
	}
	output := req.Output
	if output == "" {
		output = "base64"
	}
	encoded, err := sigilcrypto.EncodeOutput(plain.Bytes(), output)
	if err != nil {
		return err
	}
	return encode(w, map[string]any{
		"output":    encoded,
		"encoding":  output,
		"info":      info,
		"plainSize": plain.Len(),
	})
}

type dataRequest struct {
	Data      string `json:"data"`
	Encoding  string `json:"encoding"`
	Algorithm string `json:"algorithm"`
}

type macRequest struct {
	Data        string `json:"data"`
	Encoding    string `json:"encoding"`
	Key         string `json:"key"`
	KeyEncoding string `json:"keyEncoding"`
	Algorithm   string `json:"algorithm"`
}

type randomRequest struct {
	Kind   string `json:"kind"`
	Size   int    `json:"size"`
	Output string `json:"output"`
}

type xorRequest struct {
	Left     string `json:"left"`
	Right    string `json:"right"`
	Mode     string `json:"mode"`
	Encoding string `json:"encoding"`
	Output   string `json:"output"`
}

type signRequest struct {
	PrivatePEM string `json:"privatePem"`
	Data       string `json:"data"`
	Encoding   string `json:"encoding"`
}

type verifyRequest struct {
	PublicPEM string `json:"publicPem"`
	Signature string `json:"signature"`
	Data      string `json:"data"`
	Encoding  string `json:"encoding"`
}

type sealRequest struct {
	Data       string `json:"data"`
	Encoding   string `json:"encoding"`
	Passphrase string `json:"passphrase"`
	Iterations int    `json:"iterations"`
}

type openRequest struct {
	SealedBase64 string `json:"sealedBase64"`
	Passphrase   string `json:"passphrase"`
	Output       string `json:"output"`
}

func decode(r *http.Request, target any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxAPIBody+1))
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if len(data) > maxAPIBody {
		return fmt.Errorf("request body exceeds %d bytes", maxAPIBody)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request contains extra JSON")
	}
	return nil
}

func encode(w http.ResponseWriter, v any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func sessionToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate GUI session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="sigil-token" content="{{.Token}}">
  <title>Sigil</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <div class="app-shell">
    <aside class="rail" aria-label="Primary">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">S</span>
        <span>Sigil</span>
      </div>
      <nav class="tool-nav" id="tool-nav"></nav>
      <div class="rail-foot">
        <span class="status-dot" aria-hidden="true"></span>
        <span>Local</span>
      </div>
    </aside>
    <main class="workspace">
      <header class="topbar">
        <div>
          <h1 id="tool-title">Digest</h1>
          <p id="tool-subtitle">SHA-2 and SHA-3 message fingerprints</p>
        </div>
        <div class="engine-strip" aria-label="Engine status">
          <span>Go standard crypto</span>
          <span>Session guarded</span>
        </div>
      </header>
      <section class="work-grid">
        <div class="operation-panel">
          <div class="tabs" id="tool-tabs"></div>
          <form id="operation-form" autocomplete="off"></form>
        </div>
        <aside class="result-panel" aria-live="polite">
          <div class="result-head">
            <div>
              <h2>Result</h2>
              <p id="result-meta">No operation yet</p>
            </div>
            <div class="result-actions">
              <button class="icon-button" id="copy-result" type="button" title="Copy result" aria-label="Copy result">
                <span class="copy-glyph" aria-hidden="true"></span>
              </button>
              <button class="icon-button" id="save-result" type="button" title="Save result" aria-label="Save result">
                <span class="save-glyph" aria-hidden="true"></span>
              </button>
            </div>
          </div>
          <pre id="result-output">{}</pre>
          <div class="analysis-strip" id="analysis-strip"></div>
          <div class="activity">
            <h3>Activity</h3>
            <ol id="activity-log"></ol>
          </div>
        </aside>
      </section>
    </main>
  </div>
  <script src="/static/app.js"></script>
</body>
</html>`))
