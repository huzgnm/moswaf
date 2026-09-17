package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The last step of an ACME order only runs after a real validation has succeeded,
// which is the hardest point to reach in any test environment: an end-to-end run
// against a local authority gets as far as the challenge and stops there if the
// authority cannot resolve the domain.
//
// It is also the step where a mistake stays quiet. An incomplete chain still works
// for a browser that happens to have the intermediate cached and fails only for
// somebody else; a wrong expiry means renewal never fires and the certificate lapses
// in silence. So the two pure halves are tested directly, with a chain minted here.

// issueChain mints a leaf signed by a throwaway CA and returns both in DER, in the
// order an authority returns them: leaf first, then the issuer.
func issueChain(t *testing.T, notAfter time.Time, domains ...string) ([][]byte, *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return [][]byte{leafDER, caDER}, leafKey
}

func TestEncodeIssuedKeepsTheWholeChain(t *testing.T) {
	expires := time.Now().AddDate(0, 3, 0).Truncate(time.Second)
	chain, key := issueChain(t, expires, "shop.example.com", "www.shop.example.com")

	certPEM, keyPEM, notAfter, err := encodeIssued(chain, key)
	if err != nil {
		t.Fatalf("encodeIssued: %v", err)
	}

	// The intermediate has to be served as well, or clients without it cached fail
	if got := strings.Count(certPEM, "BEGIN CERTIFICATE"); got != 2 {
		t.Errorf("%d certificates in the PEM, want the full chain of 2", got)
	}
	if !notAfter.Equal(expires) {
		t.Errorf("expiry %s, want %s - renewal is scheduled from this", notAfter, expires)
	}

	// The pair has to actually load together: a mismatch here would only surface
	// when nginx reloads and starts refusing connections.
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("the certificate and key do not form a usable pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("www.shop.example.com"); err != nil {
		t.Errorf("the issued certificate does not cover a requested name: %v", err)
	}
}

func TestEncodeIssuedRejectsAnEmptyChain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := encodeIssued(nil, key); err == nil {
		t.Fatal("an empty chain was accepted; the site would be left with an empty certificate")
	}
}

func TestEncodeIssuedRejectsGarbage(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := encodeIssued([][]byte{[]byte("not a certificate")}, key); err == nil {
		t.Fatal("unparseable DER was accepted")
	}
}

// Every domain on the site has to reach the SAN list: browsers ignore the common
// name, so a domain that is only in the subject is simply not covered.
func TestNewCertificateRequestCarriesEveryDomain(t *testing.T) {
	domains := []string{"shop.example.com", "www.shop.example.com", "cdn.example.com"}

	csrDER, key, err := newCertificateRequest(domains)
	if err != nil {
		t.Fatalf("newCertificateRequest: %v", err)
	}
	if key == nil {
		t.Fatal("no private key was returned")
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("the CSR does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the CSR is not correctly signed: %v", err)
	}
	if len(csr.DNSNames) != len(domains) {
		t.Fatalf("CSR covers %v, want %v", csr.DNSNames, domains)
	}
	for i, d := range domains {
		if csr.DNSNames[i] != d {
			t.Errorf("SAN %d is %q, want %q", i, csr.DNSNames[i], d)
		}
	}
	if csr.Subject.CommonName != domains[0] {
		t.Errorf("common name %q, want %q", csr.Subject.CommonName, domains[0])
	}
}

func TestNewCertificateRequestNeedsADomain(t *testing.T) {
	if _, _, err := newCertificateRequest(nil); err == nil {
		t.Fatal("a CSR was built with no domains")
	}
}

// A PEM pair that round-trips through the store is what the data plane writes to
// disk, so it has to survive being parsed back exactly as nginx will parse it.
func TestEncodedPairParsesAsPEM(t *testing.T) {
	chain, key := issueChain(t, time.Now().AddDate(0, 3, 0), "example.com")
	certPEM, keyPEM, _, err := encodeIssued(chain, key)
	if err != nil {
		t.Fatal(err)
	}

	rest := []byte(certPEM)
	for i := 0; i < 2; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("certificate block %d is missing or mistyped", i)
		}
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("the private key block is missing or mistyped")
	}
}
