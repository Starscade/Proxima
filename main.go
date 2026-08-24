package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Route struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type Config struct {
	Router struct {
		DefaultUpstreamOrigin string
		Routes                []Route
	}
	TLS struct {
		PemFile string
		Domains []string
	}
}

type ProxyHandler struct {
	defaultProxy *url.URL
	routes       map[string]*url.URL
}

func NewProxyHandler(cfg Config) *ProxyHandler {
	defaultURL, err := url.Parse(cfg.Router.DefaultUpstreamOrigin)
	if err != nil {
		log.Fatalf("Invalid default destination URL %s: %v", cfg.Router.DefaultUpstreamOrigin, err)
	}

	routesMap := make(map[string]*url.URL)
	for _, r := range cfg.Router.Routes {
		u, err := url.Parse(r.Destination)
		if err != nil {
			log.Printf("Warning: Invalid destination for %s: %v", r.Source, err)
			continue
		}
		routesMap[r.Source] = u
	}

	return &ProxyHandler{
		defaultProxy: defaultURL,
		routes:       routesMap,
	}
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target, ok := p.routes[r.Host]
	if !ok {
		target = p.defaultProxy
	}

	// Construct target URL preserving the original path and query
	targetURL := *target
	targetURL.Path = r.URL.Path
	targetURL.RawQuery = r.URL.RawQuery

	proxyRequest, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Copy original headers to the proxy request
	for name, values := range r.Header {
		for _, value := range values {
			proxyRequest.Header.Add(name, value)
		}
	}

	if ok {
		// Specific route: use destination host to satisfy Virtual Hosting/Port requirements
		proxyRequest.Host = target.Host
	} else {
		// Default upstream: preserve original host so upstream can route internally
		proxyRequest.Host = r.Host
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(proxyRequest)
	if err != nil {
		log.Printf("Proxy error for %s: %v", r.Host, err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers back to the client
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream the response body back to the client
	_, _ = io.Copy(w, resp.Body)
}

func generateCAAndCert(domains []string, combinedFile string) error {
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Proxima CA",
			Organization: []string{"Proxima"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		return err
	}

	srvPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Proxima"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 398),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains,
	}

	srvDer, err := x509.CreateCertificate(rand.Reader, &template, caTmpl, &srvPriv.PublicKey, caPriv)
	if err != nil {
		return err
	}

	f, err := os.Create(combinedFile)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := x509.MarshalECPrivateKey(srvPriv)
	if err != nil {
		return err
	}

	pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: srvDer})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caDer})

	return nil
}

func main() {
	cfg := Config{}

	cfg.TLS.PemFile = os.Getenv("PROXIMA_PEM")
	if cfg.TLS.PemFile == "" {
		cfg.TLS.PemFile = "Proxima.pem"
	}

	domainsEnv := os.Getenv("PROXIMA_DOMAINS")
	if domainsEnv != "" {
		cfg.TLS.Domains = strings.Split(domainsEnv, ",")
	} else {
		cfg.TLS.Domains = []string{"localhost"}
	}

	cfg.Router.DefaultUpstreamOrigin = os.Getenv("PROXIMA_UPSTREAM_ORIGIN")
	if cfg.Router.DefaultUpstreamOrigin == "" {
		cfg.Router.DefaultUpstreamOrigin = "http://localhost:8080"
	}

	routesEnv := os.Getenv("PROXIMA_ROUTES")
	if routesEnv != "" {
		pairs := strings.Split(routesEnv, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				cfg.Router.Routes = append(cfg.Router.Routes, Route{Source: kv[0], Destination: kv[1]})
				log.Printf("Route override (ENV): %s -> %s", kv[0], kv[1])
			}
		}
	}

	cfgFile := os.Getenv("PROXIMA_CFG")
	if cfgFile != "" {
		data, err := os.ReadFile(cfgFile)
		if err != nil {
			log.Fatalf("Failed to read config file %s: %v", cfgFile, err)
		}
		var fileRoutes []Route
		if err := json.Unmarshal(data, &fileRoutes); err != nil {
			log.Fatalf("Failed to parse routes JSON: %v", err)
		}
		cfg.Router.Routes = append(cfg.Router.Routes, fileRoutes...)
		for _, r := range fileRoutes {
			log.Printf("Route override (FILE): %s -> %s", r.Source, r.Destination)
		}
	}

	hasLocalhost := false
	for _, d := range cfg.TLS.Domains {
		if d == "localhost" {
			hasLocalhost = true
		}
	}
	if !hasLocalhost {
		cfg.TLS.Domains = append(cfg.TLS.Domains, "localhost")
	}

	fullDomains := make([]string, 0)
	for _, d := range cfg.TLS.Domains {
		fullDomains = append(fullDomains, d)
		if !strings.HasPrefix(d, "*.") {
			fullDomains = append(fullDomains, "*."+d)
		}
	}

	if _, err := os.Stat(cfg.TLS.PemFile); os.IsNotExist(err) {
		log.Printf("Generating combined self-signed certificate for: %v", fullDomains)
		if err := generateCAAndCert(fullDomains, cfg.TLS.PemFile); err != nil {
			log.Fatalf("Failed to generate cert: %v", err)
		}
	}

	handler := NewProxyHandler(cfg)

	httpRedirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.Path
		if len(r.URL.RawQuery) > 0 {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})

	httpServer := &http.Server{
		Addr:    ":80",
		Handler: httpRedirect,
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.PemFile, cfg.TLS.PemFile)
	if err != nil {
		log.Fatalf("Failed to load combined PEM: %v", err)
	}

	tlsServer := &http.Server{
		Addr:    ":443",
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Starting automatic redirect server ...")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server failed: %v", err)
		}
	}()

	go func() {
		log.Printf("Starting reverse proxy ...")
		if err := tlsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("TLS server failed: %v", err)
		}
	}()

	<-stop
	log.Println("Terminating ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
	if err := tlsServer.Shutdown(ctx); err != nil {
		log.Printf("TLS shutdown error: %v", err)
	}
	log.Println("Server stopped.")
}
