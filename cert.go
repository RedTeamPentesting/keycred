package keycred

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"time"

	mathrand "math/rand"

	"github.com/RedTeamPentesting/adauth/x509ext"
	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"
)

// Credential hols both the KeyCredentialLink as well as the corresponding
// certificate and private key, including the PFX bundle.
type Credential struct {
	KeyCredentialLink *KeyCredentialLink
	Key               *rsa.PrivateKey
	Certificate       *x509.Certificate
	PFX               []byte
}

// GeneratePFXAndKeyCredentialLink generates a certificate and private key
// alongside the corresponding KeyCredentialLink with the required entries as
// well as a device ID, stub custom key information, an approximate last logon
// time stamp with the current time and a key creation time with the current
// time. The subject is reflected in the certificate common name, the DN in the
// KeyCredentialLink's DN-Binary representation. Optionally, otherName can be
// supplied which will be reflected in an otherName certificate SAN extension if it
// is not empty.
func GeneratePFXAndKeyCredentialLink(
	keySize int, subject string, dn string, otherName string, deviceID uuid.UUID, pfxPassword string,
) (*Credential, error) {
	additionalEntries := []KeyCredentialLinkEntry{
		NewKeySourceEntry(KeySourceAD),
		NewDeviceIDEntry(deviceID),
		NewCustomKeyInformationEntry(nil),
		NewKeyApproximateLastLogonTimeStampEntry(time.Now()),
		NewKeyCreationTimeEntry(time.Now()),
	}

	return GeneratePFXAndCustomKeyCredentialLink(
		keySize, subject, dn, otherName, false, pfxPassword, additionalEntries...)
}

// GeneratePFXAndKeyCredentialLink generates a certificate and private key
// alongside the corresponding KeyCredentialLink that only contains the entries
// that are compatible with validated writes
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c).
// The subject is reflected in the certificate common name, the DN in the
// KeyCredentialLink's DN-Binary representation. Optionally, otherName can be
// supplied which will be reflected in an otherName certificate SAN extension if
// it is not empty.
func GeneratePFXAndValidatedWriteCompatibleKeyCredentialLink(
	keySize int, subject string, dn string, otherName string, deviceID uuid.UUID, pfxPassword string,
) (*Credential, error) {
	additionalEntries := []KeyCredentialLinkEntry{
		NewKeySourceEntry(KeySourceAD),
		NewDeviceIDEntry(deviceID),
		NewKeyCreationTimeEntry(time.Now()),
	}

	cred, err := GeneratePFXAndCustomKeyCredentialLink(
		keySize, subject, dn, otherName, true, pfxPassword, additionalEntries...)
	if err != nil {
		return nil, err
	}

	err = cred.KeyCredentialLink.CheckValidatedWriteCompatible()
	if err != nil {
		return nil, fmt.Errorf("generated KeyCredentialLink is not compatible for validated writes: %w", err)
	}

	return cred, nil
}

// GeneratePFXAndKeyCredentialLink generates a certificate and private key
// alongside the corresponding KeyCredentialLink with custom key format, the
// required entries and user-supplied additional entries. The subject is
// reflected in the certificate common name, the DN in the KeyCredentialLink's
// DN-Binary representation. Optionally, otherName can be supplied which will be
// reflected in an otherName certificate SAN extension if it is not empty.
func GeneratePFXAndCustomKeyCredentialLink(
	keySize int, subject string, dn string, otherName string,
	derFormatted bool, pfxPassword string, additionalEntries ...KeyCredentialLinkEntry,
) (*Credential, error) {
	key, cert, err := createKeyAndCert(keySize, subject, otherName)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	kcl, err := newKeyCredentialLink(&key.PublicKey, dn, KeyUsageNGC, derFormatted, additionalEntries...)
	if err != nil {
		return nil, fmt.Errorf("generate KeyCredentialLink: %w", err)
	}

	pfxEncoder := pkcs12.Passwordless
	if pfxPassword != "" {
		pfxEncoder = pkcs12.Modern
	}

	pfx, err := pfxEncoder.Encode(key, cert, nil, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("build PFX: %w", err)
	}

	return &Credential{
		KeyCredentialLink: kcl,
		Key:               key,
		Certificate:       cert,
		PFX:               pfx,
	}, nil
}

func createKeyAndCert(keySize int, subject string, otherName string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(mathrand.Intn(math.MaxInt))),
		Issuer:       pkix.Name{CommonName: subject},
		Subject:      pkix.Name{CommonName: subject},
		KeyUsage:     x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    time.Now().Add(-40 * 365 * 24 * time.Hour),
		NotAfter:     time.Now().Add(40 * 365 * 24 * time.Hour),
	}

	if otherName != "" {
		otherNameExtension, err := x509ext.NewOtherNameExtensionFromUPNs(otherName)
		if err != nil {
			return nil, nil, fmt.Errorf("generate otherName extension: %w", err)
		}

		template.ExtraExtensions = append(template.ExtraExtensions, otherNameExtension)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	return key, cert, nil
}
