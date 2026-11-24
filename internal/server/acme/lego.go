package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/ionos"
	"github.com/go-acme/lego/v4/registration"
)

// acmeClient is the part of a lego client the issuer uses.
type acmeClient interface {
	Register() (*registration.Resource, error)
	Obtain(domains []string) (certPEM, keyPEM []byte, err error)
}

// connectACME creates a lego client for the account and directory and sets
// its DNS-01 provider. lego fetches the directory here: this is the first
// contact with the CA. A variable for tests.
var connectACME = func(acct *acmeAccount, directory string, provider challenge.Provider) (acmeClient, error) {
	client, err := lego.NewClient(legoConfig(acct, directory))
	if err != nil {
		return nil, fmt.Errorf("lego client: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("set dns-01: %w", err)
	}
	return legoClient{client}, nil
}

type legoClient struct{ c *lego.Client }

func (l legoClient) Register() (*registration.Resource, error) {
	return l.c.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}

func (l legoClient) Obtain(domains []string) ([]byte, []byte, error) {
	res, err := l.c.Certificate.Obtain(certificate.ObtainRequest{Domains: domains, Bundle: true})
	if err != nil {
		return nil, nil, err
	}
	return res.Certificate, res.PrivateKey, nil
}

// legoIssuer obtains certificates through lego. It is created from local
// state only; it connects to the CA and registers the account in its first
// Obtain, so that every contact with the CA happens inside an attempt the
// backoff marker covers.
type legoIssuer struct {
	dir, directory string
	acct           *acmeAccount
	provider       challenge.Provider
	client         acmeClient // nil until connected and registered
}

// Obtain connects (once), registers a new account (once) and obtains the
// certificate. Its errors occur after contact with the CA and are not
// permanent: they go through the backoff.
func (l *legoIssuer) Obtain(domains []string) ([]byte, []byte, error) {
	if l.client == nil {
		client, err := connectACME(l.acct, l.directory, l.provider)
		if err != nil {
			return nil, nil, err
		}
		if !l.acct.Registered() {
			reg, err := client.Register()
			if err != nil {
				return nil, nil, fmt.Errorf("register account: %w", err)
			}
			l.acct.Registration = reg
			if err := saveAccount(l.dir, l.acct); err != nil {
				// Registering again with the same key returns the same
				// account, so the next attempt can repeat it.
				l.acct.Registration = nil
				return nil, nil, fmt.Errorf("save account: %w", err)
			}
		}
		l.client = client
	}
	return l.client.Obtain(domains)
}

// legoConfig returns the lego configuration for the account and the ACME
// directory URL.
func legoConfig(acct *acmeAccount, directory string) *lego.Config {
	cfg := lego.NewConfig(acct)
	cfg.CADirURL = directory
	cfg.Certificate.KeyType = certcrypto.EC256
	return cfg
}

// newDNSProvider is the DNS-01 provider of the config; a variable for tests.
var newDNSProvider = func(name string) (challenge.Provider, error) {
	switch name {
	case "ionos":
		p, err := ionos.NewDNSProvider()
		if err != nil {
			return nil, fmt.Errorf("ionos provider (check IONOS_API_KEY env): %w", err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("unsupported dns_provider %q", name)
}

// errAccountWrite marks a failure to store a newly created account key: a
// full or read-only disk, which waiting can cure.
var errAccountWrite = errors.New("account file cannot be written")

// newLegoIssuer loads or creates the ACME account in dir and sets up the DNS
// provider; it does not contact the CA. Errors that waiting cannot cure (an
// existing account file that cannot be read or parsed, a DNS provider
// without credentials) are permanent.
func newLegoIssuer(opts Options, dir, directory string) (Issuer, error) {
	acct, err := loadOrCreateAccount(dir, opts.Email)
	if err != nil {
		if errors.Is(err, errAccountWrite) {
			return nil, fmt.Errorf("acme account: %w", err)
		}
		return nil, permanent(fmt.Errorf("acme account: %w", err))
	}
	provider, err := newDNSProvider(opts.DNSProvider)
	if err != nil {
		return nil, permanent(err)
	}
	return &legoIssuer{dir: dir, directory: directory, acct: acct, provider: provider}, nil
}

// --- account persistence ---

type acmeAccount struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration,omitempty"`
	KeyPEM       []byte                 `json:"key_pem"`
	key          crypto.PrivateKey
}

func (a *acmeAccount) GetEmail() string                        { return a.Email }
func (a *acmeAccount) GetRegistration() *registration.Resource { return a.Registration }
func (a *acmeAccount) GetPrivateKey() crypto.PrivateKey        { return a.key }
func (a *acmeAccount) Registered() bool                        { return a.Registration != nil }

// loadOrCreateAccount loads the account of dir. A new account (key) is
// created only when the account file does not exist.
func loadOrCreateAccount(dir, email string) (*acmeAccount, error) {
	path := filepath.Join(dir, accountFile)
	b, err := readFile(path)
	if err == nil {
		return parseAccount(b)
	}
	if !errors.Is(err, os.ErrNotExist) {
		// Unreadable is not absent: a new account here would orphan the
		// registered one and its rate-limit history.
		return nil, fmt.Errorf("read %s: %w", accountFile, err)
	}
	// Create fresh account.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	acct := &acmeAccount{Email: email, KeyPEM: keyPEM, key: key}
	if err := saveAccount(dir, acct); err != nil {
		return nil, fmt.Errorf("%w: %w", errAccountWrite, err)
	}
	return acct, nil
}

// parseAccount parses an account file, key included.
func parseAccount(raw []byte) (*acmeAccount, error) {
	var acct acmeAccount
	if err := json.Unmarshal(raw, &acct); err != nil {
		return nil, fmt.Errorf("parse %s: %w", accountFile, err)
	}
	block, _ := pem.Decode(acct.KeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block in key", accountFile)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	acct.key = key
	return &acct, nil
}

func saveAccount(dir string, acct *acmeAccount) error {
	b, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, accountFile), b)
}
