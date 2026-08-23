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
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Override struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type Config struct {
	Log struct {
		Level string `json:"level"`
	} `json:"log"`
	Router struct {
		DefaultDestination string     `json:"default_destination"`
		Overrides          []Override `json:"overrides"`
	} `json:"router"`
	TLS struct {
		PemFile string   `json:"pem_file"`
		Domains []string `json:"domains"`
	} `json:"tls"`
}

type ProxyHandler struct {
	routes       map[string]*url.URL
	defaultProxy *url.URL
	proxy        *httputil.ReverseProxy
}

func NewProxyHandler(cfg Config) *ProxyHandler {
	routes := make(map[string]*url.URL)
	for _, ovr := range cfg.Router.Overrides {
		u, err := url.Parse(ovr.Destination)
		if err != nil {
			log.Fatalf("Invalid destination URL %s: %v", ovr.Destination, err)
		}
		routes[ovr.Source] = u
		log.Printf("Route configured: %s -> %s", ovr.Source, ovr.Destination)
	}

	defaultURL, err := url.Parse(cfg.Router.DefaultDestination)
	if err != nil {
		log.Fatalf("Invalid default destination URL %s: %v", cfg.Router.DefaultDestination, err)
	}

	ph := &ProxyHandler{
		routes:       routes,
		defaultProxy: defaultURL,
	}

	// Use a single proxy instance for all requests
	ph.proxy = httputil.NewSingleHostReverseProxy(defaultURL)
	ph.proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// The Director is the "router". It modifies the request on the fly.
	originalDirector := ph.proxy.Director
	ph.proxy.Director = func(req *http.Request) {
		target, ok := ph.routes[req.Host]
		if !ok {
			target = ph.defaultProxy
		}

		// Call original director for standard header setup
		originalDirector(req)

		// Override the destination based on the lookup
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		// Preserve the incoming Host header for the target server
		req.Host = req.Host
	}

	return ph
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
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
	cfgPath := os.Getenv("PROXIMA_CFG")
	if cfgPath == "" {
		cfgPath = "Proxima.json"
	}

	cfg := Config{}
	file, err := os.Open(cfgPath)
	if err != nil {
		log.Printf("Config file %s not found or inaccessible, using defaults", cfgPath)
	} else {
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&cfg); err != nil {
			log.Printf("Failed to decode config JSON: %v, using defaults", err)
		}
		file.Close()
	}

	if cfg.TLS.PemFile == "" {
		cfg.TLS.PemFile = "Proxima.pem"
	}

	if len(cfg.TLS.Domains) == 0 {
		cfg.TLS.Domains = []string{"localhost"}
	} else {
		hasLocalhost := false
		for _, d := range cfg.TLS.Domains {
			if d == "localhost" {
				hasLocalhost = true
			}
		}
		if !hasLocalhost {
			cfg.TLS.Domains = append(cfg.TLS.Domains, "localhost")
		}
	}

	if cfg.Router.DefaultDestination == "" {
		cfg.Router.DefaultDestination = "http://localhost:8080"
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
	log.Println("Terminating...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
	if err := tlsServer.Shutdown(ctx); err != nil {
		log.Printf("TLS shutdown error: %v", err)
	}
	log.Println("Server stopped")
}
