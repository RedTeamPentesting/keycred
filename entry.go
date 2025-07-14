package keycred

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	TypeKeyID                            uint8 = 0x01
	TypeKeyHash                          uint8 = 0x02
	TypeKeyMaterial                      uint8 = 0x03
	TypeKeyUsage                         uint8 = 0x04
	TypeKeySource                        uint8 = 0x05
	TypeDeviceId                         uint8 = 0x06
	TypeCustomKeyInformation             uint8 = 0x07
	TypeKeyApproximateLastLogonTimeStamp uint8 = 0x08
	TypeKeyCreationTime                  uint8 = 0x09
)

type KeyCredentialLinkEntry interface {
	RawValue() []byte
	Type() string
	String() string
	Bytes() []byte
	Entry() *RawEntry
}

type RawEntry struct {
	Length     uint16
	Identifier uint8
	Value      []byte
}

// Entry returns the raw uninterpreted entry consisting only of length,
// identifier and value.
func (re *RawEntry) Entry() *RawEntry {
	return re
}

// Bytes returns the binary representation of the entry.
func (re *RawEntry) Bytes() []byte {
	return packBytes(binary.LittleEndian, re.Length, re.Identifier, re.Value)
}

// String returns a human readable representation of the entry.
func (re *RawEntry) String() string {
	return fmt.Sprintf("RawEntry(Length=%d, Identifier=%s, Value=%s)",
		re.Length, re.Type(), base64.RawStdEncoding.EncodeToString(re.RawValue()))
}

// RawValue makes the binary value of the entry accessible though an
// KeyCredentialLinkEntry interface.
func (re *RawEntry) RawValue() []byte {
	return re.Value
}

// Type returns the human readable name of the entry type.
func (re *RawEntry) Type() string {
	switch re.Identifier {
	case TypeKeyID:
		return "KeyID"
	case TypeKeyHash:
		return "KeyHash"
	case TypeKeyMaterial:
		return "KeyMaterial"
	case TypeKeyUsage:
		return "KeyUsage"
	case TypeKeySource:
		return "KeySource"
	case TypeDeviceId:
		return "DeviceID"
	case TypeCustomKeyInformation:
		return "CustomInformation"
	case TypeKeyApproximateLastLogonTimeStamp:
		return "KeyApproximateLastLogonTimeStamp"
	case TypeKeyCreationTime:
		return "KeyCreationTime"
	default:
		return fmt.Sprintf("Unknown Type (0x%x)", re.Identifier)
	}
}

// UnknownEntry represents an entry whose identifier is not known and which
// therefore cannot be interpreted.
type UnknownEntry struct {
	*RawEntry
}

func (ue *UnknownEntry) String() string {
	return fmt.Sprintf("UnknownEntry: Identifier=%d, Length=%d, Value=%s",
		ue.Identifier, ue.Length, base64.RawStdEncoding.EncodeToString(ue.RawValue()))
}

type KeyIDEntry struct {
	*RawEntry
}

func (keyIDEntry *KeyIDEntry) KeyID() string {
	return hex.EncodeToString(keyIDEntry.RawValue())
}

func (keyIDEntry *KeyIDEntry) String() string {
	return "KeyID: " + keyIDEntry.KeyID()
}

func (keyIDEntry *KeyIDEntry) Matches(material KeyCredentialLinkEntry) bool {
	jwkme, ok := material.(*JSONWebKeyMaterialEntry)
	if ok {
		return bytes.Equal(keyIDEntry.RawValue(), jwkme.JSON.KeyID)
	}

	materialID, err := NewKeyIDEntry(material, Version2)
	if err != nil {
		return false
	}

	return bytes.Equal(keyIDEntry.RawValue(), materialID.RawValue())
}

func (keyIDEntry *KeyIDEntry) MatchesString(keyID string) bool {
	rawKeyID, err := hex.DecodeString(keyID)
	if err != nil {
		return false
	}

	return bytes.Equal(keyIDEntry.Value, rawKeyID)
}

func NewKeyIDEntry(keyMaterial KeyCredentialLinkEntry, _ Version) (*KeyIDEntry, error) {
	switch km := keyMaterial.(type) {
	case *JSONWebKeyMaterialEntry:
		return &KeyIDEntry{
			RawEntry: &RawEntry{
				Length:     uint16(len(km.JSON.KeyID)),
				Identifier: TypeKeyID,
				Value:      km.JSON.KeyID,
			},
		}, nil
	case *KeyMaterialEntry, *FIDOKeyMaterialEntry:
		// According to
		// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7
		// the key ID should be the SHA256 hash of the Value field of the
		// KeyMaterial entry, which should be agnostic of the type of key
		// material, but for FIDO keys this does not seem to match. We do it
		// according to spec anyway, until we find out how the key ID is
		// supposed to differ for FIDO keys.
		sha256Hash := sha256.New()
		sha256Hash.Write(keyMaterial.RawValue())
		rawKeyID := sha256Hash.Sum(nil)

		keyIDEntry := &KeyIDEntry{
			RawEntry: &RawEntry{
				Length:     uint16(len(rawKeyID)),
				Identifier: TypeKeyID,
				Value:      rawKeyID,
			},
		}

		return keyIDEntry, nil
	default:
		return nil, fmt.Errorf("%T is not key material", keyMaterial)
	}
}

func AsKeyIDEntry(entry *RawEntry, version Version) (*KeyIDEntry, error) {
	if len(entry.RawValue()) == 0 {
		return nil, fmt.Errorf("no data")
	}

	return &KeyIDEntry{RawEntry: entry}, nil
}

type KeyHashEntry struct {
	*RawEntry
}

func (kh *KeyHashEntry) String() string {
	return "KeyHash: " + hex.EncodeToString(kh.RawValue())
}

func (kh *KeyHashEntry) Validate(followingEntries []KeyCredentialLinkEntry) bool {
	return bytes.Equal(kh.RawValue(), NewKeyHashEntry(followingEntries).RawValue())
}

func NewKeyHashEntry(followingEntries []KeyCredentialLinkEntry) *KeyHashEntry {
	sha256Hash := sha256.New()

	for _, entry := range followingEntries {
		sha256Hash.Write(entry.Bytes())
	}

	hash := sha256Hash.Sum(nil)

	return &KeyHashEntry{RawEntry: &RawEntry{
		Length:     uint16(len(hash)),
		Identifier: TypeKeyHash,
		Value:      hash,
	}}
}

func AsKeyHashEntry(entry *RawEntry, _ Version) (*KeyHashEntry, error) {
	if len(entry.RawValue()) == 0 {
		return nil, fmt.Errorf("no data")
	}

	return &KeyHashEntry{RawEntry: entry}, nil
}

func AsAppropriateKeyMaterialEntry(entry *RawEntry, version Version) (KeyCredentialLinkEntry, error) {
	testContent := struct {
		AuthData []byte   `json:"authData"`
		X5C      [][]byte `json:"x5c"`

		KeyType string `json:"kty"`
		KeyID   string `json:"kid"`
	}{}

	rawValue := entry.RawValue()
	switch {
	case len(rawValue) == 0:
		return nil, fmt.Errorf("data is empty")
	case rawValue[0] == '{':
		err := json.Unmarshal(rawValue, &testContent)
		if err != nil {
			return nil, fmt.Errorf("key material seems to be JSON encoded but it cannot be decode: %w", err)
		}

		switch {
		case len(testContent.AuthData) > 0 || len(testContent.X5C) > 0:
			return AsFIDOKeyMaterialEntry(entry, version)
		case testContent.KeyID != "" || testContent.KeyType != "":
			return AsJSONWebKeyMaterialEntry(entry, version)
		default:
			return nil, fmt.Errorf("JSON key material seems to be neither FIDO nor JSON Web Key")
		}
	default:
		return AsKeyMaterialEntry(entry, version)
	}
}

const (
	KeyTypeRSAPublic      = 0x31415352
	KeyTypeRSAPrivate     = 0x32415352
	KeyTypeRSAFullPrivate = 0x33415352
)

type KeyMaterialEntry struct {
	*RawEntry
	keyType        uint32
	keySize        uint32
	key            *rsa.PublicKey
	isDERFormatted bool
}

func (km *KeyMaterialEntry) KeyType() string {
	res := strconv.Itoa(int(km.keySize)) + " Bit "

	switch km.keyType {
	case KeyTypeRSAPublic:
		res += "RSA Public"
	case KeyTypeRSAPrivate:
		res += "RSA Private"
	case KeyTypeRSAFullPrivate:
		res += "RSA Full Private"
	default:
		res += fmt.Sprintf("Unknown (0x%x)", km.keyType)
	}

	res += " Key"
	if km.isDERFormatted {
		res += " (DER Formatted)"
	}

	return res
}

func (km *KeyMaterialEntry) Key() *rsa.PublicKey {
	return km.key
}

func (km *KeyMaterialEntry) String() string {
	return "KeyMaterial: " + km.KeyType()
}

func (km *KeyMaterialEntry) DetailedString() string {
	return km.String() + fmt.Sprintf(" (E=%d, N=0x%x)", km.key.E, km.key.N)
}

type JSONWebKeyMaterialEntry struct {
	*RawEntry
	JSON struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		X       string `json:"x"`
		Y       string `json:"y"`
		KeyID   []byte `json:"kid"`
	}
}

func (jwkme *JSONWebKeyMaterialEntry) String() string {
	return fmt.Sprintf("JSONWebKeyMaterial: %s", string(jwkme.RawValue()))
}

func AsJSONWebKeyMaterialEntry(entry *RawEntry, _ Version) (*JSONWebKeyMaterialEntry, error) {
	jwkme := &JSONWebKeyMaterialEntry{
		RawEntry: entry,
	}

	err := json.Unmarshal(entry.RawValue(), &jwkme.JSON)
	if err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	return jwkme, nil
}

type FIDOKeyMaterialEntry struct {
	*RawEntry
	JSON struct {
		Version     int      `json:"version"`
		AuthData    []byte   `json:"authData"`
		X5C         [][]byte `json:"x5c"`
		DisplayName string   `json:"displayName"`
	}
	DisplayName string
	// Certificates holds the certificates from the x5c JSON field. The first
	// certificate is expected to be the attestation certificate and the rest
	// are the certificate chain which may not consist of actual x509
	// certificates. In this case, the corresponding entry in this slice is nil
	// and the raw data can be retrieved from the x5c JSON
	// field at the same index.
	Certificates []*x509.Certificate
	// This field is currently not exported because the decoding is not
	// implemented completely. The raw binary authenticator data can be accesses
	// through JSON.AuthData.
	authenticatorData *fidoAuthData
}

func (fkm *FIDOKeyMaterialEntry) String() string {
	certStrs := make([]string, 0, len(fkm.Certificates))

	for i, cert := range fkm.Certificates {
		if cert == nil && i <= len(fkm.JSON.X5C) {
			certStrs = append(certStrs, base64.StdEncoding.EncodeToString(fkm.JSON.X5C[i]))
		} else {
			certStrs = append(certStrs,
				fmt.Sprintf("{Subject:%s, Issuer=%s}", cert.Subject.CommonName, cert.Issuer.CommonName))
		}
	}

	var flags []string

	if fkm.authenticatorData.Flags&fidoAuthDataFlagUserPresent > 0 {
		flags = append(flags, "UserPresent")
	}

	if fkm.authenticatorData.Flags&fidoAuthDataFlagUserVerified > 0 {
		flags = append(flags, "UserVerified")
	}

	if fkm.authenticatorData.Flags&fidoAuthDataFlagUserAttestedCredentialDataIncluded > 0 {
		flags = append(flags, "AttestedCredentialDataIncluded")
	}

	if fkm.authenticatorData.Flags&fidoAuthDataFlagUserExtensionDataIncluded > 0 {
		flags = append(flags, "ExtensionDataIncluded")
	}

	return fmt.Sprintf(
		"FIDOKeyMaterial: Display Name: %s, RP ID Hash: %x, Flags: %s, Signature Count: %d, %s, Certificates: [%s]",
		fkm.DisplayName, fkm.authenticatorData.RPIDHash, strings.Join(flags, "|"),
		fkm.authenticatorData.SignCount, humanReadableAADGUI(fkm.authenticatorData.attestedCredentialData.AAGUID),
		strings.Join(certStrs, ", "))
}

func AsFIDOKeyMaterialEntry(entry *RawEntry, _ Version) (*FIDOKeyMaterialEntry, error) {
	kme := &FIDOKeyMaterialEntry{
		RawEntry: entry,
	}

	err := json.Unmarshal(entry.RawValue(), &kme.JSON)
	if err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	kme.DisplayName = kme.JSON.DisplayName

	for i, certBytes := range kme.JSON.X5C {
		cert, err := x509.ParseCertificate(certBytes)

		// The first certificate should be the attestation certificate, and the
		// following certificates should be the chain. All of them *should* be
		// x509 certs but in practice they sometimes seem to be something else,
		// parsing errors in the chain will be ignored.
		switch {
		case err != nil && i == 0:
			return nil, fmt.Errorf("parse X5C certificate at index %d: %w", i, err)
		case err == nil:
			kme.Certificates = append(kme.Certificates, cert)
		default:
			kme.Certificates = append(kme.Certificates, nil)
		}
	}

	kme.authenticatorData, err = parseFIDOAuthData(kme.JSON.AuthData)
	if err != nil {
		return nil, fmt.Errorf("parse authenticator data: %w", err)
	}

	return kme, nil
}

func NewKeyMaterialEntry(key *rsa.PublicKey, derFormatted bool, _ Version) (*KeyMaterialEntry, error) {
	keyMaterial, err := MarshalPublicKeyMaterial(key, derFormatted)
	if err != nil {
		return nil, fmt.Errorf("marshal key material: %w", err)
	}

	return &KeyMaterialEntry{
		RawEntry: &RawEntry{
			Length:     uint16(len(keyMaterial)),
			Identifier: TypeKeyMaterial,
			Value:      keyMaterial,
		},
		keyType:        KeyTypeRSAPublic,
		keySize:        uint32(8 * key.Size()),
		key:            key,
		isDERFormatted: derFormatted,
	}, nil
}

func AsKeyMaterialEntry(entry *RawEntry, _ Version) (*KeyMaterialEntry, error) {
	key, isDer, err := UnmarshalPublicKeyMaterial(entry.RawValue())
	if err != nil {
		return nil, err
	}

	return &KeyMaterialEntry{
		RawEntry:       entry,
		keySize:        uint32(8 * key.Size()),
		keyType:        KeyTypeRSAPublic,
		key:            key,
		isDERFormatted: isDer,
	}, nil
}

const (
	KeyUsageAdminKey          uint8 = 0
	KeyUsageNGC               uint8 = 1
	KeyUsageSTK               uint8 = 2
	KeyUsageBitlockerRecovery uint8 = 3
	KeyUsageOther             uint8 = 4
	KeyUsageFIDO              uint8 = 7
	KeyUsageFEK               uint8 = 8
)

type KeyUsageEntry struct {
	*RawEntry
	usage int
}

func (ku *KeyUsageEntry) Usage() int {
	return ku.usage
}

func (ku *KeyUsageEntry) Is(usage uint8) bool {
	return ku.usage == int(usage)
}

func (ku *KeyUsageEntry) UsageString() string {
	if ku.usage < 0 {
		return string(ku.RawValue())
	}

	switch ku.RawValue()[0] {
	case KeyUsageAdminKey:
		return "AdminKey (Pin-Reset Key)"
	case KeyUsageNGC:
		return "NGC (Next Generation Credential)"
	case KeyUsageSTK:
		return "STK (Transport Key Attached to a Device Object)"
	case KeyUsageBitlockerRecovery:
		return "BitlockerRecovery"
	case KeyUsageOther:
		return "Other"
	case KeyUsageFIDO:
		return "FIDO (Fast IDentity Online Key)"
	case KeyUsageFEK:
		return "FEK (File Encryption Key)"
	default:
		return fmt.Sprintf("Unknown (0x%x)", ku.RawValue()[0])
	}
}

func (ku *KeyUsageEntry) String() string {
	return "KeyUsage: " + ku.UsageString()
}

func NewKeyUsageEntry(usage uint8) *KeyUsageEntry {
	return &KeyUsageEntry{
		RawEntry: &RawEntry{
			Length:     1,
			Identifier: TypeKeyUsage,
			Value:      []byte{usage},
		},
		usage: int(usage),
	}
}

func NewLegacyKeyUsageEntry(usage string) *KeyUsageEntry {
	return &KeyUsageEntry{
		RawEntry: &RawEntry{
			Length:     uint16(len(usage)),
			Identifier: TypeKeyUsage,
			Value:      []byte(usage),
		},
		usage: -1,
	}
}

func AsKeyUsageEntry(entry *RawEntry, _ Version) (*KeyUsageEntry, error) {
	ku := &KeyUsageEntry{RawEntry: entry}

	switch len(entry.RawValue()) {
	case 0:
		return nil, fmt.Errorf("no data")
	case 1:
		ku.usage = int(entry.RawValue()[0])
	default:
		ku.usage = -1
	}

	return ku, nil
}

const (
	KeySourceAD      uint8 = 0
	KeySourceEntraID uint8 = 1
)

type KeySourceEntry struct {
	*RawEntry
	source uint8
}

func (ks *KeySourceEntry) Value() uint8 {
	return ks.source
}

func (ks *KeySourceEntry) Source() uint8 {
	return ks.source
}

func (ks *KeySourceEntry) SourceString() string {
	switch ks.source {
	case KeySourceAD:
		return "AD"
	case KeySourceEntraID:
		return "Entra ID"
	default:
		return fmt.Sprintf("Unknown (0x%x)", ks.source)
	}
}

func (ks *KeySourceEntry) String() string {
	return "KeySource: " + ks.SourceString()
}

func NewKeySourceEntry(source uint8) *KeySourceEntry {
	return &KeySourceEntry{
		RawEntry: &RawEntry{
			Length:     1,
			Identifier: TypeKeySource,
			Value:      []byte{source},
		},
	}
}

func AsKeySourceEntry(entry *RawEntry, _ Version) (*KeySourceEntry, error) {
	if len(entry.RawValue()) == 0 {
		return nil, fmt.Errorf("no data")
	}

	return &KeySourceEntry{RawEntry: entry, source: entry.RawValue()[0]}, nil
}

type DeviceIDEntry struct {
	*RawEntry
	guid uuid.UUID
}

func (di *DeviceIDEntry) GUID() uuid.UUID {
	return di.guid
}

func (di *DeviceIDEntry) String() string {
	return "DeviceID: " + di.guid.String()
}

func NewDeviceIDEntry(guid uuid.UUID) *DeviceIDEntry {
	return &DeviceIDEntry{
		RawEntry: &RawEntry{
			Length:     uint16(len(guid)),
			Identifier: TypeDeviceId,
			Value:      guid[:],
		},
		guid: guid,
	}
}

func AsDeviceIDEntry(entry *RawEntry, _ Version) (*DeviceIDEntry, error) {
	if len(entry.RawValue()) != 16 {
		return nil, fmt.Errorf("got %d bytes instead of 16", len(entry.RawValue()))
	}

	di := &DeviceIDEntry{RawEntry: entry}

	return di, di.guid.UnmarshalBinary(entry.RawValue())
}

type CustomKeyInformationEntry struct {
	*RawEntry
	Info *CustomKeyInformation
}

func (cki *CustomKeyInformationEntry) String() string {
	return "CustomKeyInformation: " + cki.Info.String()
}

func NewCustomKeyInformationEntry(kci *CustomKeyInformation) *CustomKeyInformationEntry {
	if kci == nil {
		kci = &CustomKeyInformation{Version: 1}
	}

	return &CustomKeyInformationEntry{
		RawEntry: &RawEntry{
			Length:     2,
			Identifier: TypeCustomKeyInformation,
			Value:      kci.Bytes(),
		},
		Info: kci,
	}
}

func AsCustomKeyInformationEntry(entry *RawEntry, _ Version) (*CustomKeyInformationEntry, error) {
	info, err := ParseCustomKeyInformation(entry.RawValue(), false)
	if err != nil {
		return nil, err
	}

	cki := &CustomKeyInformationEntry{
		RawEntry: entry,
		Info:     info,
	}

	return cki, nil
}

type KeyApproximateLastLogonTimeStampEntry struct {
	*RawEntry
	time time.Time
}

func (lastLogon *KeyApproximateLastLogonTimeStampEntry) Time() time.Time {
	return lastLogon.time
}

func (lastLogon *KeyApproximateLastLogonTimeStampEntry) String() string {
	if lastLogon.time.IsZero() {
		return "KeyCreationTime: <empty>"
	}

	return "KeyApproximateLastLogonTimeStamp: " + lastLogon.time.Format("2006-01-02 15:04:05 MST")
}

func NewKeyApproximateLastLogonTimeStampEntry(t time.Time) *KeyApproximateLastLogonTimeStampEntry {
	timestamp := TimeAsFileTimeBytes(t)

	return &KeyApproximateLastLogonTimeStampEntry{
		RawEntry: &RawEntry{
			Length:     uint16(len(timestamp)),
			Identifier: TypeKeyApproximateLastLogonTimeStamp,
			Value:      timestamp,
		},
		time: t,
	}
}

func AsKeyApproximateLastLogonTimeStampEntry(
	entry *RawEntry, _ Version,
) (*KeyApproximateLastLogonTimeStampEntry, error) {
	if len(entry.RawValue()) != 8 {
		return nil, fmt.Errorf("got %d bytes instead of 8", len(entry.RawValue()))
	}

	lastLogon := &KeyApproximateLastLogonTimeStampEntry{
		RawEntry: entry,
		time:     interpretTime(binary.LittleEndian.Uint64(entry.RawValue())),
	}

	return lastLogon, nil
}

type KeyCreationTimeEntry struct {
	*RawEntry
	time time.Time
}

func (creationTime *KeyCreationTimeEntry) Time() time.Time {
	return creationTime.time
}

func (creationTime *KeyCreationTimeEntry) String() string {
	if creationTime.time.IsZero() {
		return "KeyCreationTime: <empty>"
	}

	return "KeyCreationTime: " + creationTime.time.Format("2006-01-02 15:04:05 MST")
}

func NewKeyCreationTimeEntry(t time.Time) *KeyCreationTimeEntry {
	timestamp := TimeAsFileTimeBytes(t)

	return &KeyCreationTimeEntry{
		RawEntry: &RawEntry{
			Length:     uint16(len(timestamp)),
			Identifier: TypeKeyCreationTime,
			Value:      timestamp,
		},
		time: t,
	}
}

func AsKeyCreationTimeEntry(entry *RawEntry, _ Version) (*KeyCreationTimeEntry, error) {
	if len(entry.RawValue()) != 8 {
		return nil, fmt.Errorf("got %d bytes instead of 8", len(entry.RawValue()))
	}

	lastLogon := &KeyCreationTimeEntry{
		RawEntry: entry,
		time:     interpretTime(binary.LittleEndian.Uint64(entry.RawValue())),
	}

	return lastLogon, nil
}

// UnparsableEntry represents an entry with a known identifier that could not be
// parsed according to the rules for that identifier.
type UnparsableEntry struct {
	*RawEntry
	parseErr error
}

func (ue *UnparsableEntry) String() string {
	return fmt.Sprintf("UnparsableEntry: Identifier=%s, Length=%d, Value=%s, Error=%v",
		ue.Type(), ue.Length, base64.RawStdEncoding.EncodeToString(ue.RawValue()), ue.parseErr)
}

func NewUnparsableEntry(entry *RawEntry, err error) *UnparsableEntry {
	return &UnparsableEntry{
		RawEntry: entry,
		parseErr: err,
	}
}

func interpretTime(value uint64) time.Time {
	if value == 0 {
		return time.Time{}
	}

	fileTime := TimeFromFileTime(value)

	// if the year looks plausible as FileTime, interpret it as FileTime
	if fileTime.Year() > 1900 {
		return fileTime
	}

	// Interpret the time as C# DateTime instead:
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/f05212bd-57f4-4c4b-9d98-b84c7c658054

	ticks := int64(value) & 0x3FFFFFFFFFFFFFFF         // split of timezone flag
	seconds := int64(float64(ticks) / math.Pow(10, 7)) // convert from 100ns ticks to seconds

	// work around the fact that the maximum time.Duration is way too short for
	// this calulation, so we add the maximum duration as often as we need

	var (
		d                         = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
		maxDuration time.Duration = 1<<63 - 1
		maxSeconds                = int64(math.Floor(float64(maxDuration) / float64(time.Second)))
	)

	for seconds > 0 {
		if seconds > maxSeconds {
			d = d.Add(time.Duration(maxSeconds) * time.Second)
			seconds -= maxSeconds
		} else {
			d = d.Add(time.Duration(seconds) * time.Second)
			seconds = 0
		}
	}

	return d
}
