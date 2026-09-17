// Command moswafd la control plane cua MosWAF:
// REST API + dashboard admin (cong rieng), dong bo chinh sach xuong data plane,
// va thu gom attack log tu OpenResty ve Postgres.
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
		healthcheck   = flag.Bool("healthcheck", false, "kiem tra dich vu roi thoat (dung cho docker healthcheck)")
		resetPassword = flag.String("reset-password", "", "dat lai mat khau admin roi thoat")
		showVersion   = flag.Bool("version", false, "in phien ban roi thoat")
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

	if err := run(cfg); err != nil {
		log.Fatalf("khong khoi dong duoc: %v", err)
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
		return fmt.Errorf("khong ket noi duoc redis: %w", err)
	}

	// --- day cau hinh xuong data plane ---
	pub := engine.NewPublisher(db, rdb, cfg.SitesDir, cfg.CertsDir, cfg.ProxySync)
	if err := pub.Publish(ctx); err != nil {
		// Khong chet han: admin van vao dashboard duoc de xu ly
		log.Printf("canh bao: chua day duoc cau hinh ban dau: %v", err)
	}

	// --- thu gom log + don dep ---
	consumer := engine.NewConsumer(db, rdb)
	consumer.OnChange = pub.Publish
	consumer.Run(ctx)

	// --- HTTPS cho dashboard ---
	cert, err := loadOrCreateCert(cfg.AdminTLS)
	if err != nil {
		return fmt.Errorf("chung chi dashboard: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.New(cfg, db, rdb, pub).Handler(),
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
		log.Printf("dashboard admin dang lang nghe tren https://0.0.0.0%s", cfg.Listen)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server dung bat thuong: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("nhan tin hieu dung, dang tat...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// ensureAdmin tao tai khoan quan tri dau tien tu bien moi truong.
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
		log.Printf("CHU Y: chua dat MOSWAF_ADMIN_PASSWORD, mat khau tam thoi la: %s", pass)
	}
	if err := db.CreateUser(ctx, cfg.AdminUser, pass); err != nil {
		return fmt.Errorf("tao tai khoan admin that bai: %w", err)
	}
	log.Printf("da tao tai khoan quan tri %q", cfg.AdminUser)
	return nil
}

func doResetPassword(cfg *config.Config, newPass string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.Open(ctx, cfg.DBDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "khong ket noi duoc DB:", err)
		return 1
	}
	defer db.Close()

	if err := db.SetPassword(ctx, cfg.AdminUser, newPass); err != nil {
		fmt.Fprintln(os.Stderr, "doi mat khau that bai:", err)
		return 1
	}
	fmt.Println("da doi mat khau cho", cfg.AdminUser)
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
		fmt.Fprintln(os.Stderr, "trang thai:", resp.Status)
		return 1
	}
	fmt.Println("ok")
	return 0
}

// loadOrCreateCert dung chung chi tu ky cho dashboard. Dashboard nam o cong
// rieng va thuong truy cap bang IP nen khong xin duoc chung chi cong cong;
// admin co the thay bang chung chi that bang cach de file cert.pem/key.pem
// vao dung thu muc.
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
	log.Printf("da sinh chung chi tu ky cho dashboard tai %s", dir)

	return tls.X509KeyPair(certPEM, keyPEM)
}
