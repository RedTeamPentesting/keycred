package keycred

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Version holds the version of a KEYCREDENTIALLINK_BLOB
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d4b9b239-dbe8-4475-b6f9-745612c64ed0).
type Version uint32

// String returns the string representation a KeyCredentialLink version.
func (v Version) String() string {
	switch v {
	case Version0:
		return "0"
	case Version1:
		return "1"
	case Version2:
		return "2"
	default:
		return fmt.Sprintf("0x%x", uint32(v))
	}
}

const (
	Version0 Version = 0x0
	Version1 Version = 0x00000100
	Version2 Version = 0x00000200
)

// KeyCredentialLink holds the KEYCREDENTIALLINK_BLOB structure
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f3f01e95-6d0c-4fe6-8b43-d585167658fa)
// alongside a DN such that a can correspond to a DB-Binary representation
// (https://learn.microsoft.com/en-us/windows/win32/adschema/s-object-dn-binary).
type KeyCredentialLink struct {
	DN string

	Version Version
	Entries []KeyCredentialLinkEntry
}

// NewKeyCredentialLink returns a version 2 KEYCREDENTIALLINK_BLOB
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f3f01e95-6d0c-4fe6-8b43-d585167658fa)
// with the minimum required entries as well as user-supplied additional
// entries.
func NewKeyCredentialLink(
	key *rsa.PublicKey, dn string, usage uint8, additionalEntries ...KeyCredentialLinkEntry,
) (*KeyCredentialLink, error) {
	return newKeyCredentialLink(key, dn, usage, false, additionalEntries...)
}

// NewDERKeyCredentialLink is like NewKeyCredentialLink but with DER formatted key material.
func NewDERKeyCredentialLink(
	key *rsa.PublicKey, dn string, usage uint8, additionalEntries ...KeyCredentialLinkEntry,
) (*KeyCredentialLink, error) {
	return newKeyCredentialLink(key, dn, usage, true, additionalEntries...)
}

func newKeyCredentialLink(
	key *rsa.PublicKey, dn string, usage uint8, derFormat bool, additionalEntries ...KeyCredentialLinkEntry,
) (*KeyCredentialLink, error) {
	keyMaterialEntry, err := NewKeyMaterialEntry(key, derFormat, Version2)
	if err != nil {
		return nil, fmt.Errorf("create KeyMaterialEntry: %w", err)
	}

	keyIDEntry, err := NewKeyIDEntry(keyMaterialEntry, Version2)
	if err != nil {
		return nil, fmt.Errorf("create KeyIDEntry: %w", err)
	}

	kcl := &KeyCredentialLink{
		DN:      dn,
		Version: Version2,
		Entries: []KeyCredentialLinkEntry{keyIDEntry},
	}

	var hashedEntries []KeyCredentialLinkEntry

	for _, entry := range additionalEntries {
		switch entry.Entry().Identifier {
		case TypeKeyMaterial, TypeKeyUsage, TypeKeyID:
			return nil, fmt.Errorf(
				"entry of type %s cannot be passed as additional entry as it is included by default",
				entry.Type())
		}
	}

	hashedEntries = append(hashedEntries, keyMaterialEntry, NewKeyUsageEntry(usage))
	hashedEntries = append(hashedEntries, additionalEntries...)

	kcl.Entries = append(kcl.Entries, NewKeyHashEntry(hashedEntries))
	kcl.Entries = append(kcl.Entries, hashedEntries...)

	return kcl, nil
}

// String returns a human readable string summarizing the information in the KeyCredentialLink.
func (kcl *KeyCredentialLink) String() string {
	return kcl.string(false)
}

// ColoredString is like String with ANSII color codes for colored terminal
// rendering.
func (kcl *KeyCredentialLink) ColoredString() string {
	return kcl.string(true)
}

func (kcl *KeyCredentialLink) string(colors bool) string {
	style := styleFunc(colors)

	var sb strings.Builder

	var properties []string

	err := kcl.Validate()
	if err != nil {
		properties = append(properties, style(fgRed)+"Invalid: "+err.Error()+style())
	} else {
		properties = append(properties, style(fgGreen)+"Valid"+style())
	}

	err = kcl.CheckValidatedWriteCompatible()
	if err == nil {
		properties = append(properties, style(fgBlue)+"Validated Write Compatible"+style())
	}

	if kcl.DN != "" {
		properties = append(properties, style(faint)+"DN: "+kcl.DN+style())
	}

	fmt.Fprintf(&sb, "%sKeyCredentialLink%s v%s (%s):\n",
		style(bold), style(), kcl.Version.String(), strings.Join(properties, ", "))

	for _, entry := range kcl.Entries {
		fmt.Fprintf(&sb, " • ")

		_, unparsable := entry.(*UnparsableEntry)

		parts := strings.SplitN(entry.String(), ":", 2)

		switch {
		case unparsable:
			fmt.Fprintln(&sb, style(fgYellow)+entry.String()+style())
		case len(parts) == 2:
			fmt.Fprintln(&sb, style(faint)+parts[0]+":"+style()+parts[1])
		default:
			fmt.Fprintln(&sb, entry.String())
		}
	}

	return strings.TrimSpace(sb.String())
}

func (kcl *KeyCredentialLink) parseEntry(rawEntry *RawEntry) (KeyCredentialLinkEntry, error) {
	switch rawEntry.Identifier {
	case TypeKeyID:
		return AsKeyIDEntry(rawEntry, kcl.Version)
	case TypeKeyHash:
		return AsKeyHashEntry(rawEntry, kcl.Version)
	case TypeKeyMaterial:
		return AsAppropriateKeyMaterialEntry(rawEntry, kcl.Version)
	case TypeKeyUsage:
		return AsKeyUsageEntry(rawEntry, kcl.Version)
	case TypeKeySource:
		return AsKeySourceEntry(rawEntry, kcl.Version)
	case TypeDeviceId:
		return AsDeviceIDEntry(rawEntry, kcl.Version)
	case TypeCustomKeyInformation:
		return AsCustomKeyInformationEntry(rawEntry, kcl.Version)
	case TypeKeyApproximateLastLogonTimeStamp:
		return AsKeyApproximateLastLogonTimeStampEntry(rawEntry, kcl.Version)
	case TypeKeyCreationTime:
		return AsKeyCreationTimeEntry(rawEntry, kcl.Version)
	default:
		return &UnknownEntry{RawEntry: rawEntry}, nil
	}
}

// Get returns the first entry of the given type. If no such entry exists, it
// returns nil. Note that Get does not ensure that the returned value type
// corresponds to the type ID, only that the entry identifier matches the input.
func (kcl *KeyCredentialLink) Get(entryType uint8) KeyCredentialLinkEntry {
	for _, entry := range kcl.Entries {
		if entry.Entry().Identifier == entryType {
			return entry
		}
	}

	return nil
}

// Bytes returns the binary representation of the KEYCREDENTIALLINK_BLOB
// structure
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f3f01e95-6d0c-4fe6-8b43-d585167658fa).
func (kcl *KeyCredentialLink) Bytes() []byte {
	var buf bytes.Buffer

	err := writeBinary(&buf, binary.LittleEndian, kcl.Version)
	if err != nil {
		panic(err.Error())
	}

	for _, entry := range kcl.Entries {
		err = writeBinary(&buf, binary.LittleEndian, entry.Bytes())
		if err != nil {
			panic(err.Error())
		}
	}

	return buf.Bytes()
}

// Validate checks if the KeyCredentialLink contains all entries are present
// that *MUST* be included according to the specification
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7).
// It also checks wether these entries as well as version fields are valid (e.g.
// key hash and key ID are correct).
func (kcl *KeyCredentialLink) Validate() error {
	return kcl.validate(false)
}

// ValidateStrict is like Validate but it fails when an unparsable entry is encountered.
func (kcl *KeyCredentialLink) ValidateStrict() error {
	return kcl.validate(true)
}

func (kcl *KeyCredentialLink) validate(strict bool) error {
	presentEntries := map[uint8]bool{}

	var validationErrors []error

	if kcl.Version != Version2 {
		validationErrors = append(validationErrors, fmt.Errorf("invalid version (%d)", kcl.Version))
	}

	for i, entry := range kcl.Entries {
		if presentEntries[entry.Entry().Identifier] {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate entry: %s", entry.Type()))
		}

		presentEntries[entry.Entry().Identifier] = true

		_, ok := entry.(*UnparsableEntry)
		if ok {
			if strict {
				validationErrors = append(validationErrors, fmt.Errorf("unparsable entry (%s)", entry.Type()))
			}

			continue
		}

		switch e := entry.(type) {
		case *KeyHashEntry:
			if !e.Validate(kcl.Entries[i+1:]) {
				validationErrors = append(validationErrors, fmt.Errorf("invalid KeyHash at index %d", i))
			}
		case *KeyIDEntry:
			switch km := kcl.Get(TypeKeyMaterial).(type) {
			case *KeyMaterialEntry, *JSONWebKeyMaterialEntry, *UnparsableEntry:
				if !e.Matches(km) {
					validationErrors = append(validationErrors, fmt.Errorf("key ID does not match key material"))
				}
			case *FIDOKeyMaterialEntry:
				validationErrors = append(validationErrors, fmt.Errorf("validation of FIDO key material ID is not supported"))
			default:
				validationErrors = append(validationErrors, fmt.Errorf("cannot find key material to verify key ID"))
			}
		}
	}

	if !presentEntries[TypeKeyID] {
		validationErrors = append(validationErrors, fmt.Errorf("KeyID entry not present"))
	}

	if !presentEntries[TypeKeyMaterial] {
		validationErrors = append(validationErrors, fmt.Errorf("KeyMaterial entry not present"))
	}

	if !presentEntries[TypeKeyUsage] {
		validationErrors = append(validationErrors, fmt.Errorf("KeyUsage entry not present"))
	}

	return joinErrorsWithComma(validationErrors...)
}

// CheckValidatedWriteCompatible checks whether the KeyCredentialLink conforms
// to the rules defined in section 3.1.1.5.3.1.1.6 of the Active Directory
// Technical Specification (MS-ADTS) that have to be followed when modifying the
// msDS-KeyCredentialLink attribute with RIGHT_DS_WRITE_PROPERTY_EXTENDED
// permissions instead of RIGHT_DS_WRITE_PROPERTY as is the case for computer
// accounts modifying their own KeyCredentialLinks
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c).
// Note that Microsoft currently does not actually enforce most of these rules
// (as of 2024).
func (kcl *KeyCredentialLink) CheckValidatedWriteCompatible() error {
	err := kcl.Validate()
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	keyUsage, ok := kcl.Get(TypeKeyUsage).(*KeyUsageEntry)
	if !ok {
		return fmt.Errorf("unexpected type for KeyUsage entry: %T", kcl.Get(TypeKeyUsage))
	}

	if !keyUsage.Is(KeyUsageNGC) {
		return fmt.Errorf("KeyUsage is %s (%d) instead of NGC", keyUsage.UsageString(), keyUsage.Usage())
	}

	keySourceEntryInterface := kcl.Get(TypeKeySource)
	if keySourceEntryInterface == nil {
		return fmt.Errorf("KeySource entry missing")
	}

	keySource, ok := keySourceEntryInterface.(*KeySourceEntry)
	if !ok {
		return fmt.Errorf("unexpected type for KeyUsage entry: %T", kcl.Get(TypeKeyUsage))
	}

	if keySource.Source() != KeySourceAD {
		return fmt.Errorf("KeySource is %s instead of AD", keySource.SourceString())
	}

	customKeyInformation := kcl.Get(TypeCustomKeyInformation)
	if customKeyInformation != nil {
		return fmt.Errorf("CustomKeyInformation is present")
	}

	approximateLastLogonTimeStamp := kcl.Get(TypeKeyApproximateLastLogonTimeStamp)
	if approximateLastLogonTimeStamp != nil {
		return fmt.Errorf("ApproximateLastLogonTimeStamp is present")
	}

	return nil
}

// DNWithBinary returns the DN-Binary representation of the KeyCredentialLink
// that is stored in LDAP
// (https://learn.microsoft.com/en-us/windows/win32/adschema/s-object-dn-binary).
func (kcl *KeyCredentialLink) DNWithBinary() string {
	hexBytes := strings.ToUpper(hex.EncodeToString(kcl.Bytes()))

	return fmt.Sprintf("B:%d:%s:%s", len(hexBytes), hexBytes, kcl.DN)
}

// ParseBlob parses a KeyCredentialLink from raw binary data. Since the binary
// representation does not include the DN, it can be passed as an optional
// parameter.
func ParseBlob(data []byte, dn string) (*KeyCredentialLink, error) {
	keyCred := &KeyCredentialLink{
		DN: dn,
	}

	consumer := newConsumer(data, binary.LittleEndian)
	keyCred.Version = Version(consumer.Uint32())

	for consumer.Remaining() > 0 {
		length := consumer.Uint16()
		rawEntry := &RawEntry{
			Length:     length,
			Identifier: consumer.Byte(),
			Value:      consumer.Bytes(int(length)),
		}

		parsedEntry, err := keyCred.parseEntry(rawEntry)
		if err != nil {
			parsedEntry = NewUnparsableEntry(rawEntry, err)
		}

		keyCred.Entries = append(keyCred.Entries, parsedEntry)
	}

	return keyCred, consumer.Error()
}

// ParseDNWithBinary parses the DN-Binary string representation of a
// KeyCredentialLink as it is stored in LDAP
// (https://learn.microsoft.com/en-us/windows/win32/adschema/s-object-dn-binary).
// If the returned KeyCredentialLink is not modified, it is guaranteed that
// calling '.DNWithBinary()' on it reproduces the input string of
// 'ParseDNWithBinary' exactly.
func ParseDNWithBinary(keyCredentialLinkString string) (*KeyCredentialLink, error) {
	parts := strings.Split(keyCredentialLinkString, ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("unexpected number of elements in DNWithBinary structure: %d", len(parts))
	}

	if parts[0] != "B" {
		return nil, fmt.Errorf("unexpected type: %q, expected %q", parts[0], "B")
	}

	length, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parse length %q: %w", parts[1], err)
	}

	if len(parts[2]) != length {
		return nil, fmt.Errorf("data length mismatch: advertized=%d, actual=%d", length, len(parts[2]))
	}

	data, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode data section: %w", err)
	}

	kcl, err := ParseBlob(data, parts[3])
	if err != nil {
		return nil, fmt.Errorf("parse KeyCredentialLinkBlob: %w", err)
	}

	if kcl.DNWithBinary() != keyCredentialLinkString {
		return nil, fmt.Errorf("original and parsed DNWithBinary do not match")
	}

	return kcl, nil
}

// FormatKeyCredentials formats a multiple KeyCredentialLinks with optional
// color support for terminal rendering.
func FormatKeyCredentials(kcls []*KeyCredentialLink, includeRaw bool, colored bool) string {
	style := styleFunc(colored)

	if len(kcls) == 0 {
		return ""
	}

	var (
		sb      = &strings.Builder{}
		padding = len(strconv.Itoa(len(kcls)))
	)

	for i, kcl := range kcls {
		prefix := fmt.Sprintf(fmt.Sprintf("➔ %%%dd:", padding), i+1)
		prefixSize := utf8.RuneCountInString(prefix)

		var keyCredentialLinkString string
		if colored {
			keyCredentialLinkString = kcl.ColoredString()
		} else {
			keyCredentialLinkString = kcl.String()
		}

		fmt.Fprintf(sb, "%s", prefix)
		fmt.Fprintln(sb, " "+strings.ReplaceAll(keyCredentialLinkString, "\n", "\n"+strings.Repeat(" ", prefixSize)))

		if includeRaw {
			fmt.Fprintln(sb, strings.Repeat(" ", prefixSize), style(faint)+"» Raw: "+kcl.DNWithBinary()+style())
		}

		if i < len(kcls)-1 {
			fmt.Fprintln(sb)
		}
	}

	return strings.TrimSpace(sb.String())
}

func joinErrorsWithComma(errs ...error) error {
	n := 0

	for _, err := range errs {
		if err != nil {
			n++
		}
	}

	if n == 0 {
		return nil
	}

	e := &multipleErrs{
		errs: make([]error, 0, n),
	}

	for _, err := range errs {
		if err != nil {
			e.errs = append(e.errs, err)
		}
	}

	return e
}

//nolint:errname
type multipleErrs struct {
	errs []error
}

func (e *multipleErrs) Error() string {
	if len(e.errs) == 0 {
		return ""
	}

	errStr := e.errs[0].Error()
	for _, err := range e.errs[1:] {
		errStr += ", " + err.Error()
	}

	return errStr
}

func (e *multipleErrs) Unwrap() []error {
	return e.errs
}
