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
// domainsNotCovered lists the site's domains the stored certificate does not
// name.
//
// A certificate is issued for the domains a site had at the time. Add one
// afterwards and the stored certificate is still valid, still weeks from expiry,
// and simply does not cover the new name - so without this check nothing ever
// asks for a new one, and the added domain is served the wrong certificate until
// the old one approaches expiry. That can be two months of browser warnings on a
// domain the operator added and reasonably assumed was handled.
func domainsNotCovered(s *store.Site) []string {
	if s.TLSCert == "" || len(s.Domains) == 0 {
		return nil
	}
	block, _ := pem.Decode([]byte(s.TLSCert))
	if block == nil {
		return nil // unreadable: expiry and the rest of the checks still apply
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	covered := make(map[string]bool, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		covered[strings.ToLower(n)] = true
	}

	var missing []string
	for _, d := range s.Domains {
		if !covered[strings.ToLower(strings.TrimSuffix(d, "."))] {
			missing = append(missing, d)
		}
	}
	return missing
}

// CertificateWanted reports whether a site needs a certificate at all, ignoring
// any back-off after a failure.
//
// Separate from NeedsCertificate because the two questions have different
// answers and different callers. The renewal sweep must respect the back-off -
// that is what stops a broken DNS record from hammering the authority. The
// dashboard's button exists precisely to retry immediately after fixing DNS, so
// it must not be refused by that back-off; what it must be refused by is having
// nothing to do, which is this.
func CertificateWanted(s *store.Site, now time.Time) (bool, string) {
	if !s.Enabled || !s.AcmeEnabled {
		return false, ""
	}
	if s.TLSCert == "" || s.CertExpiresAt == nil {
		return true, "no certificate yet"
	}
	if now.Add(renewBefore).After(*s.CertExpiresAt) {
		return true, "expires " + s.CertExpiresAt.Format(time.RFC3339)
	}
	if missing := domainsNotCovered(s); len(missing) > 0 {
		return true, "the certificate does not cover " + strings.Join(missing, ", ")
	}
	return false, ""
}

func NeedsCertificate(s *store.Site, now time.Time) (bool, string) {
	want, reason := CertificateWanted(s, now)
	if !want {
		return false, ""
	}
	// Back off after a failure so a broken DNS record cannot hammer the CA
	if s.AcmeLastTry != nil && s.AcmeLastError != "" &&
		now.Sub(*s.AcmeLastTry) < retryAfterFailure {
		return false, ""
	}
	return true, reason
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

	csr, key, err := newCertificateRequest(site.Domains)
	if err != nil {
		return err
	}

	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalising the order: %w", err)
	}

	certPEM, keyPEM, notAfter, err := encodeIssued(chain, key)
	if err != nil {
		return err
	}

	return c.db.StoreCertificate(ctx, site.ID, certPEM, keyPEM, notAfter)
}

// newCertificateRequest builds the CSR and its private key for a set of domains.
//
// Split out from Issue so it can be tested without a certificate authority: every
// domain has to end up in the SAN list, because a browser ignores the common name
// and a missing SAN means the certificate simply does not cover that host.
func newCertificateRequest(domains []string) ([]byte, *ecdsa.PrivateKey, error) {
	if len(domains) == 0 {
		return nil, nil, fmt.Errorf("a certificate needs at least one domain")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("building the CSR: %w", err)
	}
	return csr, key, nil
}

// encodeIssued turns what the authority returned into the two PEM blocks the data
// plane serves, and reads the expiry that drives renewal.
//
// Also split out for testing. It is the last step of an order and therefore the one
// piece that only ever runs after a real validation has succeeded - the part hardest
// to reach in a test environment, and the part where a mistake is silent: an
// incomplete chain still serves fine to a browser that already has the intermediate
// cached, and only fails for someone else.
func encodeIssued(chain [][]byte, key *ecdsa.PrivateKey) (certPEM, keyPEM string, notAfter time.Time, err error) {
	if len(chain) == 0 {
		return "", "", time.Time{}, fmt.Errorf("the authority returned an empty chain")
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("parsing the issued certificate: %w", err)
	}

	// Every element, not just the leaf: nginx has to serve the intermediates too.
	var certs strings.Builder
	for _, der := range chain {
		if err := pem.Encode(&certs, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return "", "", time.Time{}, err
		}
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certs.String(), string(keyPEMBytes), leaf.NotAfter, nil
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
