package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	ctls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA represents a Certificate Authority that signs multiple certificate types
type CA struct {
	RootCert *x509.Certificate
	RootPriv any // Typically *rsa.PrivateKey for best compatibility
	cacheMu  sync.RWMutex
	cache    map[string]*certCacheEntry
	genMu    sync.Mutex
	genLocks map[string]*sync.Mutex
	CRLURL   string
	AIAURL   string
}

type certCacheEntry struct {
	Certs  []ctls.Certificate
	expiry time.Time
}

// NewCA creates a single RSA 2048 Root CA
func NewCA() (*CA, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	skid := sha1.Sum(pubBytes)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Antigravity Network Kit CA",
			Organization: []string{"Antigravity Security Lab"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 10 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        skid[:],
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)

	return &CA{
		RootCert: cert,
		RootPriv: priv,
		cache:    make(map[string]*certCacheEntry),
		genLocks: make(map[string]*sync.Mutex),
	}, nil
}

func (ca *CA) GetCertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.RootCert.Raw,
	})
}

func (ca *CA) SetCRLURL(url string) {
	ca.CRLURL = url
}

func (ca *CA) SetAIAURL(url string) {
	ca.AIAURL = url
}

func (ca *CA) GetKeyPEM() []byte {
	if rsaKey, ok := ca.RootPriv.(*rsa.PrivateKey); ok {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		})
	}
	return nil
}

// LoadCA correctly loads the Root CA from existing PEM data
func LoadCA(certPem, keyPem []byte) (*CA, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	block, _ = pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	var priv any
	var errKey error
	if block.Type == "RSA PRIVATE KEY" {
		priv, errKey = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "EC PRIVATE KEY" {
		priv, errKey = x509.ParseECPrivateKey(block.Bytes)
	} else {
		priv, errKey = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if errKey != nil {
		return nil, errKey
	}

	return &CA{
		RootCert: cert,
		RootPriv: priv,
		cache:    make(map[string]*certCacheEntry),
		genLocks: make(map[string]*sync.Mutex),
	}, nil
}

// GenerateMirroredCert signs a certificate by mirroring the properties of a template certificate
func (ca *CA) GenerateMirroredCert(hostname string, templateCert *x509.Certificate) ([]ctls.Certificate, error) {
	ca.cacheMu.RLock()
	if entry, ok := ca.cache[hostname]; ok && time.Now().Before(entry.expiry) {
		ca.cacheMu.RUnlock()
		return entry.Certs, nil
	}
	ca.cacheMu.RUnlock()

	ca.genMu.Lock()
	hMu, ok := ca.genLocks[hostname]
	if !ok {
		hMu = &sync.Mutex{}
		ca.genLocks[hostname] = hMu
	}
	ca.genMu.Unlock()

	hMu.Lock()
	defer hMu.Unlock()

	// Double check cache
	ca.cacheMu.RLock()
	if entry, ok := ca.cache[hostname]; ok && time.Now().Before(entry.expiry) {
		ca.cacheMu.RUnlock()
		return entry.Certs, nil
	}
	ca.cacheMu.RUnlock()

	now := time.Now()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Create template by copying safe fields from real cert if provided, otherwise use default
	var newTemplate x509.Certificate
	if templateCert != nil {
		newTemplate.Subject = templateCert.Subject
		newTemplate.Subject.CommonName = hostname // Ensure CN matches what client requested
		newTemplate.DNSNames = templateCert.DNSNames
		newTemplate.IPAddresses = templateCert.IPAddresses
		newTemplate.KeyUsage = templateCert.KeyUsage
		newTemplate.ExtKeyUsage = templateCert.ExtKeyUsage
		newTemplate.BasicConstraintsValid = true
		newTemplate.IsCA = false

		// Copy essential extensions but specifically avoid all revocation, transparency, and authority info
		for _, ext := range templateCert.Extensions {
			oid := ext.Id.String()
			// Skip list:
			// - SCT (1.3.6.1.4.1.11129.2.4.2)
			// - AIA (1.3.6.1.5.5.7.1.1)
			// - CRL Distribution Points (2.5.29.31)
			// - OCSP (1.3.6.1.5.5.7.48.1)
			// - Authority Info Access (1.3.6.1.5.5.7.48.2 - technically same OID as AIA but for access)
			if strings.HasPrefix(oid, "1.3.6.1.4.1.11129.2.4.2") || // SCTs
				strings.HasPrefix(oid, "1.3.6.1.5.5.7.1.1") || // AIA
				strings.HasPrefix(oid, "2.5.29.31") || // CRL
				strings.HasPrefix(oid, "1.3.6.1.5.5.7.48.1") || // OCSP
				strings.HasPrefix(oid, "1.3.6.1.5.5.7.48.2") { // CA Issuer Info
				continue
			}
			newTemplate.ExtraExtensions = append(newTemplate.ExtraExtensions, ext)
		}

		newTemplate.SerialNumber = serial
		newTemplate.NotBefore = now.Add(-24 * time.Hour)
		newTemplate.NotAfter = now.Add(365 * 24 * time.Hour)
		newTemplate.AuthorityKeyId = ca.RootCert.SubjectKeyId

		// SChannel compatibility: CRL and AIA are critical for Windows trust
		if ca.CRLURL != "" {
			newTemplate.CRLDistributionPoints = []string{ca.CRLURL}
		}
		if ca.AIAURL != "" {
			newTemplate.IssuingCertificateURL = []string{ca.AIAURL}
		}
	} else {
		// Better default matching Google's patterns
		org := "Google Trust Services LLC"
		if strings.HasSuffix(hostname, ".google.com") || strings.HasSuffix(hostname, ".googleapis.com") {
			org = "Google LLC"
		}

		newTemplate = x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:         hostname,
				Organization:       []string{org},
				OrganizationalUnit: []string{"Cloud Infrastructure"},
				Locality:           []string{"Mountain View"},
				Province:           []string{"California"},
				Country:            []string{"US"},
			},
			NotBefore:             now.Add(-24 * time.Hour),
			NotAfter:              now.Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{hostname},
			AuthorityKeyId:        ca.RootCert.SubjectKeyId,
		}

		// SChannel compatibility
		if ca.CRLURL != "" {
			newTemplate.CRLDistributionPoints = []string{ca.CRLURL}
		}
		if ca.AIAURL != "" {
			newTemplate.IssuingCertificateURL = []string{ca.AIAURL}
		}

		if ip := net.ParseIP(hostname); ip != nil {
			newTemplate.IPAddresses = []net.IP{ip}
		}

		if strings.HasSuffix(hostname, ".googleapis.com") {
			newTemplate.DNSNames = append(newTemplate.DNSNames, "*.googleapis.com", "googleapis.com")
		} else if strings.HasSuffix(hostname, ".google.com") {
			newTemplate.DNSNames = append(newTemplate.DNSNames, "*.google.com", "google.com")
		}
	}

	// Always ensure hostname is in DNSNames/IPAddresses if not present
	if ip := net.ParseIP(hostname); ip != nil {
		ipFound := false
		for _, existingIP := range newTemplate.IPAddresses {
			if existingIP.Equal(ip) {
				ipFound = true
				break
			}
		}
		if !ipFound {
			newTemplate.IPAddresses = append(newTemplate.IPAddresses, ip)
		}
	} else {
		found := false
		for _, dns := range newTemplate.DNSNames {
			if dns == hostname {
				found = true
				break
			}
		}
		if !found {
			newTemplate.DNSNames = append(newTemplate.DNSNames, hostname)
		}
	}

	// 1. Generate ECDSA Cert (preferred)
	privEC, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubECBytes, _ := x509.MarshalPKIXPublicKey(&privEC.PublicKey)
	skidEC := sha1.Sum(pubECBytes)
	newTemplateEC := newTemplate
	newTemplateEC.SubjectKeyId = skidEC[:]
	newTemplateEC.KeyUsage = x509.KeyUsageDigitalSignature
	if templateCert != nil {
		newTemplateEC.KeyUsage = templateCert.KeyUsage
	}

	derEC, err := x509.CreateCertificate(rand.Reader, &newTemplateEC, ca.RootCert, &privEC.PublicKey, ca.RootPriv)
	if err != nil {
		return nil, err
	}
	certEC, _ := ctls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derEC}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: func() []byte { b, _ := x509.MarshalECPrivateKey(privEC); return b }()}),
	)
	certEC.Certificate = append(certEC.Certificate, ca.RootCert.Raw)

	// 2. Generate RSA Cert (fallback)
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubRSABytes, _ := x509.MarshalPKIXPublicKey(&privRSA.PublicKey)
	skidRSA := sha1.Sum(pubRSABytes)
	newTemplateRSA := newTemplate
	newTemplateRSA.SubjectKeyId = skidRSA[:]
	newTemplateRSA.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if templateCert != nil {
		newTemplateRSA.KeyUsage = templateCert.KeyUsage
	}

	derRSA, err := x509.CreateCertificate(rand.Reader, &newTemplateRSA, ca.RootCert, &privRSA.PublicKey, ca.RootPriv)
	if err != nil {
		return nil, err
	}
	certRSA, _ := ctls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derRSA}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privRSA)}),
	)
	certRSA.Certificate = append(certRSA.Certificate, ca.RootCert.Raw)

	certs := []ctls.Certificate{certEC, certRSA}
	ca.cacheMu.Lock()
	ca.cache[hostname] = &certCacheEntry{
		Certs:  certs,
		expiry: now.Add(20 * time.Hour),
	}
	ca.cacheMu.Unlock()

	return certs, nil
}

// CreateCRL generates a signed (empty) CRL using the Root CA
func (ca *CA) CreateCRL() ([]byte, error) {
	now := time.Now()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour), // Valid for 1 week
	}

	return x509.CreateRevocationList(rand.Reader, template, ca.RootCert, ca.RootPriv.(crypto.Signer))
}

// GenerateCert signs dual certificates (RSA + ECDSA) using default templates
func (ca *CA) GenerateCert(hostname string) ([]ctls.Certificate, error) {
	return ca.GenerateMirroredCert(hostname, nil)
}

// InstallToWindows programmatically installs the Root CA certificate into the Windows
// Trusted Root Certification Authorities store using certutil.
func (ca *CA) InstallToWindows() error {
	certPem := ca.GetCertPEM()
	if len(certPem) == 0 {
		return fmt.Errorf("failed to get CA certificate PEM")
	}

	// Create a temporary file for the certificate
	tmpFile := filepath.Join(os.TempDir(), "netkit_ca.crt")
	if err := os.WriteFile(tmpFile, certPem, 0644); err != nil {
		return fmt.Errorf("failed to write temporary CA file: %v", err)
	}
	defer os.Remove(tmpFile)

	fmt.Printf("[TLS] 📜 Attempting to install Root CA into Windows Trust Store...\n")

	// Use certutil to add the certificate to the "Root" store (Trusted Root Certification Authorities)
	// -addstore: Adds a certificate to a store
	// -f: Force overwrite if exists
	// "Root": The system trusted root store
	cmd := exec.Command("certutil", "-addstore", "-f", "Root", tmpFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil failed (error: %v, output: %s)", err, string(output))
	}

	fmt.Printf("[TLS] ✅ Root CA successfully installed to Windows Trust Store.\n")
	return nil
}
