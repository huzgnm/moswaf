package engine

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
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mosvpn/moswaf/control/internal/store"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/acme"
)

// Certificates are obtained over ACME HTTP-01, the only challenge type a reverse
// proxy can satisfy without touching the operator's DNS: the CA fetches
// http://<domain>/.well-known/acme-challenge/<token> on port 80, a port MosWAF
// already owns.
//
// The token reaches the data plane through Redis rather than a shared directory, so
// the two planes stay decoupled - they already share Redis for the configuration,
// and nothing new has to be mounted into both containers.
const (
	acmeTokenPrefix = "moswaf:acme:"
	acmeTokenTTL    = 10 * time.Minute

	// Let's Encrypt issues for 90 days. Renewing with 30 days left leaves three
	// weeks of retries before anything actually expires.
	renewBefore = 30 * 24 * time.Hour

	// A failed order is not retried straight away: rate limits at the CA are strict
	// and a misconfigured DNS record will not fix itself within the minute.
	retryAfterFailure = time.Hour
)

// acmeAccount is persisted in the settings table so the same account key is reused
// across restarts; registering a fresh account on every boot would burn through the
// CA's account rate limit.
type acmeAccount struct {
	KeyPEM    string `json:"key_pem"`
	Directory string `json:"directory"`
	URI       string `json:"uri"`
	Email     string `json:"email"`
}

type Certifier struct {
	db         *store.Store
	rdb        *redis.Client
	directory  string
	httpClient *http.Client
	onIssued   func(context.Context) error
}

func NewCertifier(db *store.Store, rdb *redis.Client, directory string, insecure bool,
	onIssued func(context.Context) error) *Certifier {

	if directory == "" {
		directory = acme.LetsEncryptURL
	}
	c := &Certifier{db: db, rdb: rdb, directory: directory, onIssued: onIssued}
	if insecure {
		// config.acmeInsecure has already refused to set this for anything but a
		// local test authority, but it is worth one line in the log either way.
		log.Printf("moswaf: ACME certificate verification is DISABLED for %s "+
			"(test authority only - never point this at a public CA)", directory)
		c.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return c
}

// NeedsCertificate reports whether a site should be sent through ACME now, and why.
//
// Deliberately free of I/O so the decision is testable on its own: it is what
// decides whether a live site keeps serving TLS or starts showing browser warnings.
func NeedsCertificate(s *store.Site, now time.Time) (bool, string) {
	if !s.Enabled || !s.AcmeEnabled {
		return false, ""
	}
	// Back off after a failure so a broken DNS record cannot hammer the CA
	if s.AcmeLastTry != nil && s.AcmeLastError != "" &&
		now.Sub(*s.AcmeLastTry) < retryAfterFailure {
		return false, ""
	}
	if s.TLSCert == "" || s.CertExpiresAt == nil {
		return true, "no certificate yet"
	}
	if now.Add(renewBefore).After(*s.CertExpiresAt) {
		return true, "expires " + s.CertExpiresAt.Format(time.RFC3339)
	}
	return false, ""
}

// Run checks every site on a slow loop. ACME work is rare, so the loop is cheap;
// the first pass happens shortly after startup so a fresh install does not wait.
func (c *Certifier) Run(ctx context.Context) {
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				c.sweep(ctx)
				timer.Reset(6 * time.Hour)
			}
		}
	}()
}

func (c *Certifier) sweep(ctx context.Context) {
	sites, err := c.db.ListSites(ctx)
	if err != nil {
		log.Printf("moswaf: acme sweep could not read sites: %v", err)
		return
	}

	issued := false
	for _, s := range sites {
		need, why := NeedsCertificate(s, time.Now())
		if !need {
			continue
		}
		log.Printf("moswaf: requesting a certificate for %s (%s): %s",
			s.Name, strings.Join(s.Domains, ", "), why)

		if err := c.Issue(ctx, s); err != nil {
			log.Printf("moswaf: certificate for %s failed: %v", s.Name, err)
			c.recordFailure(ctx, s, err)
			continue
		}
		log.Printf("moswaf: certificate for %s issued", s.Name)
		issued = true
	}

	// One publish for the whole sweep: writing the new certificates out and telling
	// the data plane to reload is the same work however many were renewed.
	if issued && c.onIssued != nil {
		if err := c.onIssued(ctx); err != nil {
			log.Printf("moswaf: publishing renewed certificates failed: %v", err)
		}
	}
}

func (c *Certifier) recordFailure(ctx context.Context, s *store.Site, cause error) {
	msg := cause.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	if err := c.db.RecordACMEAttempt(ctx, s.ID, msg); err != nil {
		log.Printf("moswaf: could not record the acme failure: %v", err)
	}
}

// Issue drives one ACME order from start to finish and stores the result.
func (c *Certifier) Issue(ctx context.Context, site *store.Site) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	client, err := c.client(ctx, site.AcmeEmail)
	if err != nil {
		return err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(site.Domains...))
	if err != nil {
		return fmt.Errorf("creating the order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := c.solveHTTP01(ctx, client, authzURL); err != nil {
			return err
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("waiting for the order: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: site.Domains[0]},
		DNSNames: site.Domains,
	}, key)
	if err != nil {
		return fmt.Errorf("building the CSR: %w", err)
	}

	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalising the order: %w", err)
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return fmt.Errorf("parsing the issued certificate: %w", err)
	}

	var certPEM strings.Builder
	for _, der := range chain {
		if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return c.db.StoreCertificate(ctx, site.ID, certPEM.String(), string(keyPEM), leaf.NotAfter)
}

// solveHTTP01 publishes the challenge response where the data plane can serve it,
// tells the CA to go and look, and waits for the verdict.
func (c *Certifier) solveHTTP01(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("reading the authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil // validated recently enough that the CA still trusts it
	}

	var chal *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			chal = ch
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("the CA offered no http-01 challenge for %s", authz.Identifier.Value)
	}

	response, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}

	key := acmeTokenPrefix + chal.Token
	if err := c.rdb.Set(ctx, key, response, acmeTokenTTL).Err(); err != nil {
		return fmt.Errorf("publishing the challenge token: %w", err)
	}
	defer c.rdb.Del(context.WithoutCancel(ctx), key)

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accepting the challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("the CA could not validate %s: %w", authz.Identifier.Value, err)
	}
	return nil
}

// client returns an ACME client bound to the stored account, registering one the
// first time it is needed.
func (c *Certifier) client(ctx context.Context, email string) (*acme.Client, error) {
	raw, err := c.db.GetSetting(ctx, "acme_account")
	if err != nil {
		return nil, err
	}

	var acct acmeAccount
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &acct); err != nil {
			return nil, fmt.Errorf("the stored acme account is unreadable: %w", err)
		}
	}

	// A key registered against one directory means nothing at another
	if acct.KeyPEM == "" || acct.Directory != c.directory {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		client := &acme.Client{
			Key: key, DirectoryURL: c.directory, UserAgent: "moswaf",
			HTTPClient: c.httpClient,
		}
		registered, err := client.Register(ctx, &acme.Account{
			Contact: []string{"mailto:" + email},
		}, acme.AcceptTOS)
		if err != nil {
			return nil, fmt.Errorf("registering with the CA: %w", err)
		}

		acct = acmeAccount{
			KeyPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
			Directory: c.directory,
			URI:       registered.URI,
			Email:     email,
		}
		stored, _ := json.Marshal(acct)
		if err := c.db.PutSetting(ctx, "acme_account", stored); err != nil {
			return nil, err
		}
		return client, nil
	}

	block, _ := pem.Decode([]byte(acct.KeyPEM))
	if block == nil {
		return nil, fmt.Errorf("the stored acme account key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the stored acme account key is unusable: %w", err)
	}
	return &acme.Client{
		Key: key, DirectoryURL: c.directory, UserAgent: "moswaf",
		HTTPClient: c.httpClient,
	}, nil
}
