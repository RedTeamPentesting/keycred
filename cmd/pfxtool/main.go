package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RedTeamPentesting/adauth/x509ext"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

var version string

func run() error {
	var (
		password         string
		pfxFile          string
		certFile         string
		keyFile          string
		force            bool
		inplace          bool
		originalPassword string
	)

	cobra.EnableCommandSorting = false
	rootCmd := &cobra.Command{
		Use:           binaryName(),
		Short:         "Convert certificates and keys from and to PFX files",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	flags := rootCmd.PersistentFlags()
	flags.StringVarP(&password, "password", "p", "", "PFX password")
	flags.BoolVarP(&force, "force", "f", false, "Overwrite existing output files")

	joinCmd := &cobra.Command{
		Use:           "join <cert/key.pem> <cert/key.pem>",
		Short:         "Create a PFX file by joining a PEM encoded key and cert",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return join(args[0], args[1], pfxFile, password, force)
		},
	}

	joinFlags := joinCmd.PersistentFlags()
	joinFlags.StringVarP(&pfxFile, "pfx", "o", "", "PFX output file")

	rootCmd.AddCommand(joinCmd)

	splitCmd := &cobra.Command{
		Use:           "split <store.pfx>",
		Short:         "Split a PFX file into PEM encoded key and cert",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return split(args[0], password, certFile, keyFile, force)
		},
	}

	splitFlags := splitCmd.PersistentFlags()
	splitFlags.StringVarP(&certFile, "cert", "c", "", "Certificate output file")
	splitFlags.StringVarP(&keyFile, "key", "k", "", "Key output file")

	rootCmd.AddCommand(splitCmd)

	decryptCmd := &cobra.Command{
		Use:           "decrypt <store.pfx>",
		Short:         "Remove the password from a PFX file",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return decrypt(args[0], password, pfxFile, inplace, force)
		},
	}
	decryptFlags := decryptCmd.PersistentFlags()
	decryptFlags.StringVarP(&pfxFile, "output", "o", "", "PFX output file")
	decryptFlags.BoolVar(&inplace, "inplace", false, "Decrypt PFX in place")

	rootCmd.AddCommand(decryptCmd)

	encryptCmd := &cobra.Command{
		Use:           "encrypt <store.pfx>",
		Short:         "Encrypt the PFX file with a password",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return encrypt(args[0], originalPassword, pfxFile, password, inplace, force)
		},
	}
	encryptFlags := encryptCmd.PersistentFlags()
	encryptFlags.StringVarP(&pfxFile, "output", "o", "", "PFX output file")
	encryptFlags.BoolVar(&inplace, "inplace", false, "Encrypt PFX in place")
	encryptFlags.StringVar(&originalPassword, "original-password", "", "Original password of the PFX file")

	rootCmd.AddCommand(encryptCmd)

	var verbose bool

	inspectCmd := &cobra.Command{
		Use:           "inspect <store.pfx>",
		Short:         "Inspect the contents of a PFX",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return inspect(args[0], password, verbose)
		},
	}

	inspectFlags := inspectCmd.PersistentFlags()
	inspectFlags.BoolVarP(&verbose, "verbose", "v", verbose, "Enable verbose output")

	rootCmd.AddCommand(inspectCmd)

	var (
		subjectCN        string
		upn              string
		sid              string
		keySize          int
		validity         time.Duration
		keyUsage         int
		extendedKeyUsage []int
	)

	createCmd := &cobra.Command{
		Use:           "create",
		Short:         "Create a certificate/key pair and save it as a PFX file",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if upn == "" && strings.Count(subjectCN, "@") == 1 && !cmd.PersistentFlags().Changed("upn") {
				upn = subjectCN
			}

			ekus := make([]x509.ExtKeyUsage, 0, len(extendedKeyUsage))
			for _, eku := range extendedKeyUsage {
				ekus = append(ekus, x509.ExtKeyUsage(eku))
			}

			err := create(subjectCN, upn, sid, x509.KeyUsage(keyUsage), ekus, validity,
				keySize, pfxFile, password, force)
			if err != nil {
				return err
			}

			fmt.Printf("Created PFX: %s\n\n", pfxFile)

			return inspect(pfxFile, password, false)
		},
	}

	createFlags := createCmd.PersistentFlags()
	createFlags.StringVar(&subjectCN, "cn", "", "Subject common name")
	createFlags.StringVar(&upn, "upn", "", "Alternative UPN for otherName extension")
	createFlags.StringVar(&sid, "sid", "", "User SID for certificate user mapping")
	createFlags.StringVarP(&pfxFile, "output", "o", "", "PFX output file")
	createFlags.StringVarP(&password, "password", "p", "", "PFX password")
	createFlags.IntVar(&keySize, "key-size", 2048, "Private key size in bits")
	createFlags.DurationVar(&validity, "valid-for", 0, "Period for which the certificate is valid (default ~100 years)")
	createFlags.IntVar(&keyUsage, "key-usage", int(x509.KeyUsageCertSign), "Key usage")
	createFlags.IntSliceVar(&extendedKeyUsage, "eku", []int{int(x509.ExtKeyUsageClientAuth)}, "Extended key usage")

	rootCmd.AddCommand(createCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:           "version",
		Short:         "Print the version",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if version != "" {
				fmt.Println(version)
			} else {
				fmt.Println("unknown")
			}
		},
	})

	return rootCmd.Execute()
}

func join(certOrKeyFile1 string, certOrKeyFile2 string, pfxFile string, pfxPassword string, force bool) error {
	if pfxFile == "" {
		pfxFile = tryFindPFXName(certOrKeyFile1, certOrKeyFile2)
	}

	if pfxFile == "" {
		return fmt.Errorf("specify a PFX output file")
	}

	if !force {
		_, err := os.Stat(pfxFile)
		if err == nil {
			return fmt.Errorf("PFX output file %q already exists", pfxFile)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat PFX output file: %w", err)
		}
	}

	certOrKey1PEMBytes, err := os.ReadFile(certOrKeyFile1)
	if err != nil {
		return fmt.Errorf("read certificate/key %q: %w", certOrKeyFile1, err)
	}

	isCert1, certOrKey1, err := parsePEMKeyOrCertificate(certOrKey1PEMBytes)
	if err != nil {
		return fmt.Errorf("parse certificate/key form %q: %w", certOrKeyFile1, err)
	}

	certOrKey2PEMBytes, err := os.ReadFile(certOrKeyFile2)
	if err != nil {
		return fmt.Errorf("read certificate/key %q: %w", certOrKeyFile2, err)
	}

	isCert2, certOrKey2, err := parsePEMKeyOrCertificate(certOrKey2PEMBytes)
	if err != nil {
		return fmt.Errorf("parse certificate/key from %q: %w", certOrKeyFile2, err)
	}

	var (
		certDER []byte
		keyDER  []byte
	)

	switch {
	case isCert1 && isCert2:
		return fmt.Errorf("both files are certificates: %w", err)
	case !isCert1 && !isCert2:
		return fmt.Errorf("both files are keys: %w", err)
	case isCert1 && !isCert2:
		certDER = certOrKey1
		keyDER = certOrKey2

	case !isCert1 && isCert2:
		certDER = certOrKey2
		keyDER = certOrKey1
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	pfxEncoder := pkcs12.Passwordless
	if pfxPassword != "" {
		pfxEncoder = pkcs12.Modern
	}

	pfxData, err := pfxEncoder.Encode(key, cert, nil, pfxPassword)
	if err != nil {
		return fmt.Errorf("PFX encode with password: %w", err)
	}

	err = os.WriteFile(pfxFile, pfxData, 0o600)
	if err != nil {
		return fmt.Errorf("write PFX: %w", err)
	}

	fmt.Printf("PFX written to %s\n", pfxFile)

	return nil
}

func split(pfxFile string, pfxPassword string, certFile string, keyFile string, force bool) error {
	pfxBaseName := strings.TrimSuffix(pfxFile, filepath.Ext(pfxFile))

	if certFile == "" {
		certFile = pfxBaseName + ".crt"
	}

	if keyFile == "" {
		keyFile = pfxBaseName + ".key"
	}

	_, err := os.Stat(certFile)
	if err == nil && !force {
		return fmt.Errorf("certificate output file %q already exists", certFile)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat certificate output file: %w", err)
	}

	_, err = os.Stat(keyFile)
	if err == nil && !force {
		return fmt.Errorf("key output file %q already exists", certFile)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat key output file: %w", err)
	}

	pfxData, err := os.ReadFile(pfxFile)
	if err != nil {
		return fmt.Errorf("read PFX: %w", err)
	}

	key, cert, _, err := pkcs12.DecodeChain(pfxData, pfxPassword)
	if err != nil {
		return fmt.Errorf("decode PFX: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	err = os.WriteFile(certFile, certPEM, 0o600)
	if err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	fmt.Printf("Certificate written to %s\n", certFile)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("DER encode key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	err = os.WriteFile(keyFile, keyPEM, 0o600)
	if err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	fmt.Printf("PEM key written to %s\n", keyFile)

	return nil
}

func decrypt(encryptedPFXFile string, password string, decryptedPFXFile string, inplace bool, force bool) error {
	if password == "" {
		return fmt.Errorf("specify a password")
	}

	switch {
	case decryptedPFXFile != "" && inplace:
		return fmt.Errorf("both an output file and inplace were selected simultaneously")
	case decryptedPFXFile != "" && !inplace:
		_, err := os.Stat(decryptedPFXFile)
		if err == nil && !force {
			return fmt.Errorf("key output file %q already exists", decryptedPFXFile)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat key output file: %w", err)
		}
	case inplace:
		decryptedPFXFile = encryptedPFXFile
	default:
		return fmt.Errorf("specify an output file")
	}

	encryptedPFXData, err := os.ReadFile(encryptedPFXFile)
	if err != nil {
		return fmt.Errorf("read PFX: %w", err)
	}

	key, cert, chain, err := pkcs12.DecodeChain(encryptedPFXData, password)
	if err != nil {
		return fmt.Errorf("decode PFX: %w", err)
	}

	decryptedPFXData, err := pkcs12.Modern.Encode(key, cert, chain, "")
	if err != nil {
		return fmt.Errorf("encode PFX: %w", err)
	}

	err = os.WriteFile(decryptedPFXFile, decryptedPFXData, 0o600)
	if err != nil {
		return fmt.Errorf("write decrypted PFX file: %w", err)
	}

	fmt.Printf("Decrypted PFX written to %s\n", decryptedPFXFile)

	return nil
}

func encrypt(
	unencryptedPFXFile string, originalPassword string, encryptedPFXFile string, password string, inplace bool, force bool,
) error {
	if password == "" {
		return fmt.Errorf("specify a password")
	}

	switch {
	case encryptedPFXFile != "" && inplace:
		return fmt.Errorf("both an output file and inplace were selected simultaneously")
	case encryptedPFXFile != "" && !inplace:
		_, err := os.Stat(encryptedPFXFile)
		if err == nil && !force {
			return fmt.Errorf("key output file %q already exists", encryptedPFXFile)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat key output file: %w", err)
		}
	case inplace:
		encryptedPFXFile = unencryptedPFXFile
	default:
		return fmt.Errorf("specify an output file")
	}

	pfxData, err := os.ReadFile(unencryptedPFXFile)
	if err != nil {
		return fmt.Errorf("read PFX: %w", err)
	}

	key, cert, chain, err := pkcs12.DecodeChain(pfxData, originalPassword)
	if err != nil {
		return fmt.Errorf("decode PFX: %w", err)
	}

	encryptedPFXData, err := pkcs12.Modern.Encode(key, cert, chain, password)
	if err != nil {
		return fmt.Errorf("encode PFX: %w", err)
	}

	err = os.WriteFile(encryptedPFXFile, encryptedPFXData, 0o600)
	if err != nil {
		return fmt.Errorf("write decrypted PFX file: %w", err)
	}

	fmt.Printf("Encrypted PFX written to %s\n", encryptedPFXFile)

	return nil
}

func inspect(pfxFile string, pfxPassword string, verbose bool) error {
	pfxData, err := os.ReadFile(pfxFile)
	if err != nil {
		return fmt.Errorf("read PFX: %w", err)
	}

	key, cert, chain, err := pkcs12.DecodeChain(pfxData, pfxPassword)
	if err != nil {
		return fmt.Errorf("decode PFX: %w", err)
	}

	otherNames, err := x509ext.OtherNames(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot extract UPNs: %v\n", err)
	}

	sid, err := x509ext.SID(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot extract SID: %v\n", err)
	}

	template, err := templateName(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot extract template name: %v\n", err)
	}

	fmt.Println("Certificate:")

	if len(cert.Subject.Names) > 0 {
		fmt.Printf("  Subject    : %s\n", nameAsString(cert.Subject))
	}

	if len(otherNames) > 0 {
		fmt.Println("  Other Names:")

		for _, otherName := range otherNames {
			switch otherName.ID.String() {
			case x509ext.UPNOID.String():
				var nameValue string

				_, err = asn1.UnmarshalWithParams(otherName.Value.Bytes, &nameValue, "utf8")
				if err != nil {
					nameValue = base64.StdEncoding.EncodeToString(otherName.Value.Bytes)
				}

				fmt.Printf("    UPN : %s\n", nameValue)
			case "1.3.6.1.4.1.311.25.1":
				fmt.Printf("    GUID: %s\n", tryParseASN1GUID(otherName.Value.Bytes))
			default:
				fmt.Printf("    %s: %s\n", otherName.ID, base64.StdEncoding.EncodeToString(otherName.Value.Bytes))
			}
		}
	}

	if sid != "" {
		fmt.Printf("  SID        : %s\n", sid)
	}

	if len(cert.DNSNames) > 0 {
		fmt.Printf("  DNS Names  : %s\n", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("  Emails     : %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	if len(cert.IPAddresses) > 0 {
		fmt.Printf("  IPs        : %s\n", joinStringers(cert.IPAddresses, ", "))
	}

	if len(cert.URIs) > 0 {
		fmt.Printf("  URIs       : %s\n", joinStringers(cert.URIs, ", "))
	}

	if template != "" {
		fmt.Printf("  Template   : %s\n", template)
	}

	fmt.Printf("  Issuer     : %s\n", cert.Issuer.CommonName)
	fmt.Printf("  Not Before : %s\n", cert.NotBefore)
	fmt.Printf("  Not After  : %s\n", cert.NotAfter)

	if cert.KeyUsage != 0 {
		fmt.Printf("  Key Usage  : %s\n", keyUsageString(cert.KeyUsage))
	}

	if len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) > 0 {
		fmt.Printf("  EKU        : %s\n", extUsageString(cert.ExtKeyUsage, cert.UnknownExtKeyUsage))
	}

	if cert.IsCA {
		fmt.Println("  CA Cert    : Yes")
	}

	fmt.Printf("  Public Key : %s\n", cert.PublicKeyAlgorithm)
	fmt.Printf("  Signature  : %s\n", cert.SignatureAlgorithm)

	if verbose && len(cert.CRLDistributionPoints) > 0 {
		fmt.Println("  CRL   :")

		for _, crl := range cert.CRLDistributionPoints {
			fmt.Println("    " + crl)
		}
	}

	if verbose {
		fmt.Println("  Extensions :")

		for _, ext := range cert.Extensions {
			fmt.Printf("    %s: %s\n", oidName(ext.Id), base64.StdEncoding.EncodeToString(ext.Value))
		}
	}

	keyType := strings.ToUpper(
		strings.TrimPrefix(
			strings.TrimSuffix(
				fmt.Sprintf("%T", key),
				".PrivateKey"),
			"*"))

	k, ok := key.(*rsa.PrivateKey)
	if ok {
		keyType += fmt.Sprintf(" (%d bit)", k.Size()*8)
	}

	fmt.Printf("Key Type: %s\n", keyType)

	if len(chain) > 0 {
		fmt.Printf("CA Chain with %d certificates\n", len(chain))
	}

	return nil
}

func create(
	subject string, upn string, sid string, keyUsage x509.KeyUsage, extendedKeyUsage []x509.ExtKeyUsage,
	validity time.Duration, keySize int, outputFile string, outputPass string, force bool,
) error {
	if outputFile == "" {
		return fmt.Errorf("specify an output file")
	}

	_, err := os.Stat(outputFile)
	if err == nil && !force {
		return fmt.Errorf("output file %q already exists", outputFile)
	}

	if validity == 0 {
		validity = 100 * 365 * 24 * time.Hour
	}

	if keySize == 0 {
		keySize = 2048
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	if keyUsage == 0 {
		keyUsage = x509.KeyUsageCertSign
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(mathrand.Intn(math.MaxInt))),
		Issuer:       pkix.Name{CommonName: subject},
		Subject:      pkix.Name{CommonName: subject},
		KeyUsage:     keyUsage,
		ExtKeyUsage:  extendedKeyUsage,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),
	}

	if upn != "" {
		otherNameExtension, err := x509ext.NewOtherNameExtensionFromUPNs(upn)
		if err != nil {
			return fmt.Errorf("generate otherName extension: %w", err)
		}

		template.ExtraExtensions = append(template.ExtraExtensions, otherNameExtension)
	}

	if sid != "" {
		sidExtension, err := x509ext.NewNTDSCaSecurityExt(sid)
		if err != nil {
			return fmt.Errorf("generate NTDS_CA_SECURITY_EXT extension: %w", err)
		}

		template.ExtraExtensions = append(template.ExtraExtensions, sidExtension)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	encoder := pkcs12.Passwordless
	if outputPass != "" {
		encoder = pkcs12.Modern
	}

	pfx, err := encoder.Encode(key, cert, nil, outputPass)
	if err != nil {
		return fmt.Errorf("build PFX: %w", err)
	}

	return os.WriteFile(outputFile, pfx, 0o600)
}

func parsePEMKeyOrCertificate(data []byte) (isCert bool, content []byte, err error) {
	block, rest := pem.Decode(data)
	if len(rest) != 0 {
		return false, nil, fmt.Errorf("could not decode PEM")
	}

	switch {
	case strings.Contains(strings.ToLower(block.Type), "certificate"):
		return true, block.Bytes, nil
	case strings.Contains(strings.ToLower(block.Type), "key"):
		return false, block.Bytes, nil
	default:
		return false, nil, fmt.Errorf("pem type does not contain CERTIFICATE or KEY: %q", block.Type)
	}
}

func tryFindPFXName(certName string, keyName string) string {
	certBaseName := strings.TrimSuffix(certName, filepath.Ext(certName))
	keyBaseName := strings.TrimSuffix(keyName, filepath.Ext(keyName))

	if certBaseName != keyBaseName {
		return ""
	}

	return certBaseName + ".pfx"
}

func binaryName() string {
	executable, err := os.Executable()
	if err == nil {
		return filepath.Base(executable)
	}

	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}

	return "pfxtool"
}

func keyUsageString(ku x509.KeyUsage) string {
	var kuStrings []string

	if ku&x509.KeyUsageDigitalSignature > 0 {
		kuStrings = append(kuStrings, "Digital Signature")
	}

	if ku&x509.KeyUsageContentCommitment > 0 {
		kuStrings = append(kuStrings, "Content Commitment")
	}

	if ku&x509.KeyUsageKeyEncipherment > 0 {
		kuStrings = append(kuStrings, "Key Encipherment")
	}

	if ku&x509.KeyUsageDataEncipherment > 0 {
		kuStrings = append(kuStrings, "Data Encipherment")
	}

	if ku&x509.KeyUsageKeyAgreement > 0 {
		kuStrings = append(kuStrings, "Key Agreement")
	}

	if ku&x509.KeyUsageCertSign > 0 {
		kuStrings = append(kuStrings, "Cert Sign")
	}

	if ku&x509.KeyUsageCRLSign > 0 {
		kuStrings = append(kuStrings, "CRL Sign")
	}

	if ku&x509.KeyUsageEncipherOnly > 0 {
		kuStrings = append(kuStrings, "Encipher Only")
	}

	if ku&x509.KeyUsageDecipherOnly > 0 {
		kuStrings = append(kuStrings, "Decipher Only")
	}

	return strings.Join(kuStrings, ", ")
}

func extUsageString(ekus []x509.ExtKeyUsage, unknownEKUs []asn1.ObjectIdentifier) string {
	kuStrings := make([]string, 0, len(ekus)+len(unknownEKUs))

	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			kuStrings = append(kuStrings, "Any")
		case x509.ExtKeyUsageServerAuth:
			kuStrings = append(kuStrings, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			kuStrings = append(kuStrings, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			kuStrings = append(kuStrings, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			kuStrings = append(kuStrings, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			kuStrings = append(kuStrings, "IPSec End System")
		case x509.ExtKeyUsageIPSECTunnel:
			kuStrings = append(kuStrings, "IPSec Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			kuStrings = append(kuStrings, "IPSec User")
		case x509.ExtKeyUsageTimeStamping:
			kuStrings = append(kuStrings, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			kuStrings = append(kuStrings, "OSCP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			kuStrings = append(kuStrings, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			kuStrings = append(kuStrings, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			kuStrings = append(kuStrings, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			kuStrings = append(kuStrings, "Microsoft Kernel Code Signing")
		default:
			kuStrings = append(kuStrings, fmt.Sprintf("Unknown (%d)", eku))
		}
	}

	for _, unknownEKU := range unknownEKUs {
		kuStrings = append(kuStrings, oidName(unknownEKU))
	}

	return strings.Join(kuStrings, ", ")
}

func oidName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "1.3.6.1.4.1.311.20.2.2":
		return "Smartcard Logon"
	case "1.3.6.1.5.2.3.5":
		return "KDC Authentication"
	case "1.3.6.1.4.1.311.10.3.4":
		return "EFS Crypto"
	case "2.5.29.14":
		return "Subject Key ID"
	case "2.5.29.35":
		return "CA Key ID"
	case "2.5.29.31":
		return "CRL Distribution Points"
	case "1.3.6.1.5.5.7.1.1":
		return "CA Information Access"
	case "1.3.6.1.4.1.311.21.7":
		return "Certificate Template Information"
	case "1.3.6.1.4.1.311.20.2":
		return "Certificate Template Name"
	case "2.5.29.15":
		return "Key Usage"
	case "2.5.29.37":
		return "Extended Key Usage"
	case "2.5.29.17":
		return "Subject Alternative Name"
	case "1.3.6.1.4.1.311.25.2":
		return "NTDS CA Security (SID)"
	case "1.2.840.113549.1.9.15":
		return "SMIME Capabilities"
	case "1.3.6.1.4.1.311.21.10":
		return "Certificate Application Policy"
	case "1.3.6.1.4.1.311.21.19":
		return "DS Email Replication"
	case "2.5.29.19":
		return "Basic Constraints"
	case "1.3.6.1.4.1.311.10.3.4.1":
		return "EFS Recovery"
	default:
		return oid.String()
	}
}

func templateName(cert *x509.Certificate) (string, error) {
	var (
		templateName string
		templateInfo string
	)

	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.311.20.2" {
			_, err := asn1.Unmarshal(ext.Value, &templateName)
			if err != nil {
				return "", fmt.Errorf("parse template name: %w", err)
			}
		} else if ext.Id.String() == "1.3.6.1.4.1.311.21.7" {
			var template struct {
				ID           asn1.ObjectIdentifier
				MajorVersion int
				MinorVersion int
			}

			_, err := asn1.Unmarshal(ext.Value, &template)
			if err != nil {
				return "", fmt.Errorf("parse template info: %w", err)
			}

			templateInfo = fmt.Sprintf("%s v%d.%d", template.ID, template.MajorVersion, template.MinorVersion)
		}
	}

	if templateName != "" {
		return templateName, nil
	}

	return templateInfo, nil
}

func tryParseASN1GUID(asn1Data []byte) string {
	var rawGUID []byte

	_, err := asn1.Unmarshal(asn1Data, &rawGUID)
	if err != nil {
		return base64.StdEncoding.EncodeToString(asn1Data)
	}

	if len(rawGUID) != 16 {
		return base64.StdEncoding.EncodeToString(asn1Data)
	}

	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(rawGUID[0:4]),
		binary.LittleEndian.Uint16(rawGUID[4:6]),
		binary.LittleEndian.Uint16(rawGUID[6:8]),
		rawGUID[8:10],
		rawGUID[10:])
}

func nameAsString(pkixName pkix.Name) string {
	parts := make([]string, 0, len(pkixName.Names))

	for _, name := range pkixName.Names {
		var key string

		switch name.Type.String() {
		case "2.5.4.6":
			key = "C"
		case "2.5.4.10":
			key = "O"
		case "2.5.4.11":
			key = "OU"
		case "2.5.4.3":
			key = "CN"
		case "2.5.4.5":
			key = "SERIALNUMBER"
		case "2.5.4.7":
			key = "L"
		case "2.5.4.8":
			key = "ST"
		case "2.5.4.9":
			key = "STREET"
		case "2.5.4.17":
			key = "POSTALCODE"
		case "0.9.2342.19200300.100.1.25":
			key = "DC"
		default:
			key = "{" + name.Type.String() + "}"
		}

		parts = append(parts, fmt.Sprintf("%s=%v", key, name.Value))
	}

	slices.Reverse(parts)

	return strings.Join(parts, ",")
}

func joinStringers[T fmt.Stringer](elems []T, sep string) string {
	strs := make([]string, 0, len(elems))

	for _, elem := range elems {
		strs = append(strs, elem.String())
	}

	return strings.Join(strs, sep)
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}
