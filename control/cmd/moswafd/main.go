// Command moswafd is the MosWAF control plane: the REST API and admin dashboard
// on their own port, policy publishing down to the data plane, and collection of
// the attack log from OpenResty into Postgres.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mosvpn/moswaf/control/internal/api"
	"github.com/mosvpn/moswaf/control/internal/config"
	"github.com/mosvpn/moswaf/control/internal/engine"
	"github.com/mosvpn/moswaf/control/internal/store"
	"github.com/redis/go-redis/v9"
)

var version = "0.1.0"

func main() {
	var (
		healthcheck   = flag.Bool("healthcheck", false, "check the service and exit (used by the docker healthcheck)")
		resetPassword = flag.String("reset-password", "", "reset the admin password and exit")
		showVersion   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[moswaf] ")

	cfg := config.Load()

	switch {
	case *showVersion:
		fmt.Println("moswafd", version)
		return
	case *healthcheck:
		os.Exit(doHealthcheck(cfg.Listen))
	case *resetPassword != "":
		os.Exit(doResetPassword(cfg, *resetPassword))
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("failed to start: %v", err)
	}
}

func run(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Postgres ---
	db, err := store.Open(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}
	if err := db.SeedRules(ctx); err != nil {
		return err
	}
	if err := ensureAdmin(ctx, db, cfg); err != nil {
		return err
	}

	// --- Redis ---
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("cannot connect to redis: %w", err)
	}

	// --- published crawler address ranges ---
	//
	// Seeded from the snapshot compiled into the binary, so an installation with
	// no route to the internet still recognises search engines, then refreshed on
	// its own timer. Set before the first publish so the data plane has the ranges
	// from its first configuration rather than a cycle later.
	crawlers := engine.NewCrawlers()

	// --- publish the configuration to the data plane ---
	pub := engine.NewPublisher(db, rdb, cfg)
	pub.SetCrawlers(crawlers)
	crawlers.Start(ctx, func() {
		if err := pub.Publish(ctx); err != nil {
			log.Printf("warning: refreshed the crawler ranges but could not publish them: %v", err)
		}
	})
	if err := pub.Publish(ctx); err != nil {
		// Not fatal: the admin can still reach the dashboard and fix things
		log.Printf("warning: could not publish the initial configuration: %v", err)
	}

	// --- automatic certificates ---
	certifier := engine.NewCertifier(db, rdb, cfg.ACMEDirectory, cfg.ACMEInsecure, pub.Publish)
	certifier.Run(ctx)

	// --- geolocation for the attack log ---
	//
	// Several megabytes downloaded in the background, used only to label recorded
	// events. Nothing waits on it and nothing breaks without it.
	geo := engine.NewGeoIP()
	geo.Start(ctx)

	apiServer := api.New(cfg, db, rdb, pub, certifier)
	apiServer.SetGeoIP(geo)

	// --- event collection and housekeeping ---
	consumer := engine.NewConsumer(db, rdb)
	consumer.SetGeoIP(geo)
	consumer.OnChange = pub.Publish
	consumer.Run(ctx)

	// --- HTTPS cho dashboard ---
	cert, err := loadOrCreateCert(cfg.AdminTLS)
	if err != nil {
		return fmt.Errorf("chung chi dashboard: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ErrorLog: log.New(os.Stderr, "[moswaf-http] ", log.LstdFlags),
	}

	go func() {
		log.Printf("admin dashboard listening on https://0.0.0.0%s", cfg.Listen)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server stopped unexpectedly: %v", err)
		}
	}()

	// --- the data plane's own listener ---
	//
	// Carries the site login endpoint and nothing else, on the container network
	// only. Deliberately a second server rather than another route on the one
	// above: a route is one mistake away from being reachable from the internet,
	// and a listener that is not published cannot be.
	var internal *http.Server
	if cfg.InternalListen != "" {
		internal = &http.Server{
			Addr:              cfg.InternalListen,
			Handler:           apiServer.InternalHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			ErrorLog:          log.New(os.Stderr, "[moswaf-internal] ", log.LstdFlags),
		}
		go func() {
			log.Printf("internal endpoint listening on %s (container network only)", cfg.InternalListen)
			if err := internal.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				// Not fatal. Losing this means nobody can sign in to a gated site;
				// it does not mean the dashboard or the firewall should stop.
				log.Printf("moswaf: the internal endpoint stopped: %v", err)
			}
		}()
	}

	<-ctx.Done()
	log.Println("shutdown signal received, stopping...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if internal != nil {
		_ = internal.Shutdown(shutdownCtx)
	}
	return srv.Shutdown(shutdownCtx)
}

// ensureAdmin creates the first administrator account from the environment.
func ensureAdmin(ctx context.Context, db *store.Store, cfg *config.Config) error {
	n, err := db.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	pass := cfg.AdminPassword
	if pass == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		pass = fmt.Sprintf("%x", b)
		log.Printf("NOTE: MOSWAF_ADMIN_PASSWORD is unset, temporary password is: %s", pass)
	}
	if err := db.CreateUser(ctx, cfg.AdminUser, pass); err != nil {
		return fmt.Errorf("failed to create the admin account: %w", err)
	}
	log.Printf("created administrator account %q", cfg.AdminUser)
	return nil
}

func doResetPassword(cfg *config.Config, newPass string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.Open(ctx, cfg.DBDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot connect to the database:", err)
		return 1
	}
	defer db.Close()

	if err := db.SetPassword(ctx, cfg.AdminUser, newPass); err != nil {
		fmt.Fprintln(os.Stderr, "password change failed:", err)
		return 1
	}
	fmt.Println("password changed for", cfg.AdminUser)
	return 0
}

func doHealthcheck(listen string) int {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		port = "9443"
	}
	if host == "" {
		host = "127.0.0.1"
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s:%s/api/health", host, port))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "status:", resp.Status)
		return 1
	}
	fmt.Println("ok")
	return 0
}

// loadOrCreateCert uses a self-signed certificate for the dashboard. The dashboard
// sits on its own port and is usually reached by IP, so a public certificate is not
// an option; an admin can swap in a real one by dropping cert.pem and key.pem into
// the same directory.
func loadOrCreateCert(dir string) (tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"MosWAF"}, CommonName: "MosWAF Admin"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "moswaf.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	log.Printf("generated a self-signed dashboard certificate in %s", dir)

	return tls.X509KeyPair(certPEM, keyPEM)
}
