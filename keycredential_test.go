package keycred_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/RedTeamPentesting/keycred"
	"github.com/google/uuid"
)

func TestParseDNWithBinary(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	deviceID := uuid.New()
	created := time.Now()
	lastLogon := time.Now()

	additionalProperties := []keycred.KeyCredentialLinkEntry{
		keycred.NewKeySourceEntry(keycred.KeySourceAD),
		keycred.NewDeviceIDEntry(deviceID),
		keycred.NewCustomKeyInformationEntry(nil),
		keycred.NewKeyApproximateLastLogonTimeStampEntry(lastLogon),
		keycred.NewKeyCreationTimeEntry(created),
	}

	keyCredentialLink, err := keycred.NewKeyCredentialLink(
		&key.PublicKey, "CN=Administrator,CN=Users,DC=lab,DC=redteam", keycred.KeyUsageNGC, additionalProperties...)
	if err != nil {
		t.Fatalf("generate KeyCredentialLink: %v", err)
	}

	err = keyCredentialLink.ValidateStrict()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	parsed, err := keycred.ParseDNWithBinary(keyCredentialLink.DNWithBinary())
	if err != nil {
		t.Fatalf("parse DN with binary: %v", err)
	}

	err = parsed.ValidateStrict()
	if err != nil {
		t.Fatalf("validation for parsed KeyCredentialLink failed: %v", err)
	}

	if !bytes.Equal(keyCredentialLink.Bytes(), parsed.Bytes()) {
		t.Fatalf("bytes mismatch")
	}

	if parsed.DNWithBinary() != keyCredentialLink.DNWithBinary() {
		t.Fatalf("DN with binary mismatch")
	}
}

func TestUnknownEntry(t *testing.T) {
	t.Parallel()

	keyCredentialLinkWithUnknownEntry := "B:488:0002000020000118E15C2FC5E786FC5B5" +
		"E639F0C113949C38C9F66C90F294262E56FB838F1AEE520000228585BBA3200BF8DDA36E" +
		"DA7EF4486797CCD0170C4AC4FA155D787CCA44043839B000352534131000400000300000" +
		"0800000000000000000000000010001B910045760ADA302AE2EC8D59E35F6CCF5CAF362C" +
		"BD00AFA5C2F3463B88DF5F777B72A96552288CBFAD7E76B528179F3834FD7D633CD15F0E" +
		"36A72ADC3B035575D58083A7C1B4778A5B3D949613F9382DA80B4BEE3303B8F3116053EF" +
		"052275B7EE5471E143DC4B83447801D8799199CBBF84C46AF0A54DC15AEB1095D8D41C50" +
		"10004010500630102030405:dn"

	kcl, err := keycred.ParseDNWithBinary(keyCredentialLinkWithUnknownEntry)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	found := false

	for _, entry := range kcl.Entries {
		_, ok := entry.(*keycred.UnknownEntry)
		if ok {
			found = true

			break
		}
	}

	if !found {
		t.Errorf("cloud not find unknown entry")
	}

	if kcl.DNWithBinary() != keyCredentialLinkWithUnknownEntry {
		t.Errorf("DNWithBinary changed")
	}
}

func TestUnparsableEntry(t *testing.T) {
	t.Parallel()

	keyCredentialLinkWithUnparsableEntry := "B:572:000200002000012DF5C152ECD728CC" +
		"84653DC5401079038DFBA44101E049796134F2E49EA524492000025F962E25E715FA4F9B" +
		"EC380E87EABEE8CAF92F6F6FED7217F8581E748FC89BED9B000359534131000400000300" +
		"0000800000000000000000000000010001C3A2FE33F6F9806F5AD7609E837B462C47A5CE" +
		"9D9B151F41797236B8E0D903FE42280C3E69F378A5833C3A97F605B74A12B15801FAC6F1" +
		"F4569CD579A94E2C3D6C85B7A5691CECAD83DF0F42C1ED57FDE1095D99F49E29D2804147" +
		"FF5DD0F6907873225F7FEF87D69947F673A4C0CF91499794EE26EFB1A43BD0D0042B0365" +
		"F50100040101000500100006D6C16EE7BF2C4259BDBE3C2A986738490200070100080008" +
		"E2E590D3734DDB01080009FFE590D3734DDB01:dn"

	kcl, err := keycred.ParseDNWithBinary(keyCredentialLinkWithUnparsableEntry)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	found := false

	for _, entry := range kcl.Entries {
		_, ok := entry.(*keycred.UnparsableEntry)
		if ok {
			found = true

			break
		}
	}

	if !found {
		t.Errorf("cloud not find unparsable entry")
	}

	if kcl.DNWithBinary() != keyCredentialLinkWithUnparsableEntry {
		t.Errorf("DNWithBinary changed")
	}
}

func TestValidationError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		TestName     string
		DNWithBinary string
	}{
		{
			TestName: "invalid key hash",
			DNWithBinary: "B:572:0002000020000123A78CBE91315868D1A87CCF8AA962DB2" +
				"4C5C54E852B067E5D785397057CA23720000200F7D7A567E0940FC6391565A6" +
				"AE8BE96DFBC271E408AC4026ED732B218F9D569B00035253413100040000030" +
				"00000800000000000000000000000010001B9FB57466173CC127CD491F45456" +
				"43FBEA5F8E3BAB45DB0ACE33738E2D8278ED50EED83AC04189F5B8460EDED8B" +
				"543544A11F80BAAC74572F700B6267EB770EA1F90A1D97019E7C9498B9004C9" +
				"30917B8FA4DB5B0D54F6B0872579B5932C4C53A5DB937DC1DC33EC0B6E02B30" +
				"01D3AEADED6117E56146EBBC597D234D668B0A701000401010005001000062B" +
				"E69777F9374C478E575FE409656A630200070100080008A0E091EF6E4DDB010" +
				"80009B8E091EF6E4DDB01:dn",
		},
		{
			TestName: "invalid version",
			DNWithBinary: "B:572:01000000200001630B0C3FA9B999A9CEDE417A9DD0F25F2" +
				"32E9025FBAB982D1726118C25246A0C20000212774A0BA87C064D77DCC89AF9" +
				"E78E313657F3F13F9630FBFD44955EBB88532F9B00035253413100040000030" +
				"00000800000000000000000000000010001DF9ACA662BB28087BB0A151AF931" +
				"5B51419C4EA499DA219063F1B30326D5CA6410186D79E2951D87AF858910075" +
				"7E3FF1401AD3F05E7C7162FF9B74506C008E92CD95601A36887DBD788CD3F1A" +
				"13DEA633816895828443BAD9057DFF64E9961C7BC39D4E22B624748FBB2980E" +
				"0353B529D4F442FD97632C752AF599241535EFF0100040101000500100006A3" +
				"F7A798EC8347848FC6135547E72AB70200070100080008BBBA8FD26F4DDB010" +
				"80009CFBA8FD26F4DDB01:dn",
		},
		{
			TestName: "duplicate entry",
			DNWithBinary: "B:488:00020000200001AB0567C3B8C9FB58890EA784C2244372F" +
				"4702B2294D06F4F7892966A07F328D22000024A4F38D8E0A34679722AD320B1" +
				"CA8DC115AEE0476CB37DD5AC70103A509D77129B00035253413100040000030" +
				"00000800000000000000000000000010001BF82BCE442B4E24F927034CE84D0" +
				"366F6AC049CFAEC714CDB404BBCCA1897F5E4F4A6D9469EA9D7ABC1889A0153" +
				"E4463AFB0F6128029BCAC0644268D150119220ED4AEA9354329D1C1A4F8ECBD" +
				"7BD401D4E57F1226EE1A7C804286545651A314475043C8FE3FDB5D5FE5CD6DB" +
				"001ED87DBAF21FB2EE27DD528A6BC951388467B010004010100050001000500" +
				":dn",
		},
		{
			TestName: "key material does not match key ID",
			DNWithBinary: "B:572:000200002000010039F0787791941B57B357D89350B662F" +
				"2B883B7377B83419E7A7737A0CD9B842000025C02AEC2BBCEF11F5BA512C0BC" +
				"9A665E2600D0FAB59F2631969AC1B48DBFA3F69B00035253413100040000030" +
				"00000800000000000000000000000010001BEB0AEA4251803B100067FFBDC0B" +
				"CA7148EBD69D3ECFE8AE633F737B4D57160AAE1532B6FA2FF57623D4C778E90" +
				"FA5E53D14C6DFB6E796F83EE5A0F46E78ECDA5635ECA5058B31B791BFFF492D" +
				"9DBC374863FF087721F9875FBCE7550DD05EF380BF6946342F89C7218C342D3" +
				"4A19C5AC31F17A437C7370A6BF05A1FC6B065CD01000401010005001000062C" +
				"95F564370146498312923FFA4309A20200070100080008CDEA2AE0704DDB010" +
				"80009E4EA2AE0704DDB01:dn",
		},
		{
			TestName: "no key material and no key ID",
			DNWithBinary: "B:116:0002000001000401010005001000061EF394B240734CE88" +
				"77BA0F621A5E93702000701000800080BEAB3AE714DDB0108000927EAB3AE71" +
				"4DDB01:dn",
		},
		{
			TestName: "key ID but no key material",
			DNWithBinary: "B:256:00020000200001BE6EE7480A23717D213B084C3CDCE2665" +
				"899B4A0842DEE61E85622F49BC805E3200002CBE1E442403667FE560C251078" +
				"DF0BE7DFCE43312777A1B84DC738AB045F366D01000401010005001000069FD" +
				"041037A32426E86C8EFFF62A9CD1E02000701000800084BD8AD67714DDB0108" +
				"000963D8AD67714DDB01:dn",
		},
		{
			TestName: "key usage missing",
			DNWithBinary: "B:494:00020000200001785B614F80CE2EE2C323A7F157215D414" +
				"3814B48BCEC3C9A7495C3081C4867199B000352534131000400000300000080" +
				"0000000000000000000000010001FAA195E5CA146D5C592633DFA93EFE05FCC" +
				"DB2BE84A851F6D86C99EA5F5F106836F11C188C95F2949049B8C7A637771773" +
				"E6B879E98FB55F8276730236E302BA534EED65EF2D0D763756280522D06B4B5" +
				"C89A91E37BE6622E7B2F6B71052C5E508E9E9D6A0682B624852DCCD8C8DF592" +
				"135E5F09E629B991DA5FDB91A64EDEA701000500100006922D9FAE83C248CAA" +
				"85ECC9401620A6B0200070100080008BB8F2618724DDB01080009D78F261872" +
				"4DDB01:dn",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			t.Parallel()

			keyCred, err := keycred.ParseDNWithBinary(testCase.DNWithBinary)
			if err != nil {
				t.Fatalf("parse DN with binary: %v", err)
			}

			err = keyCred.Validate()
			if err == nil {
				t.Errorf("validation of test case %q did not return an error", testCase.TestName)
			}

			err = keyCred.ValidateStrict()
			if err == nil {
				t.Errorf("strict validation of test case %q did not return an error", testCase.TestName)
			}

			if keyCred.DNWithBinary() != testCase.DNWithBinary {
				t.Errorf("DNWithBinary changed")
			}
		})
	}
}

func TestValidateStrictFail(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		TestName     string
		DNWithBinary string
	}{
		{
			TestName: "contains unparsable entry",
			DNWithBinary: "B:480:0002000020000107D73A597A9954954D53CAFEA19C87A1B6" +
				"A6C2A52E3B3BD3FC12C4A412E2DAA1200002B4912B8877FDAE4D229C28C0038A" +
				"2D8A3D49E04C0CF3817A194BD2A2F4ECAEDD9B00035253413100040000030000" +
				"00800000000000000000000000010001E072FC3E2A1EFDF3DF09E027C29E308C" +
				"F8D6F2C97A8050C60836744DCE7C3E7E3D2EA46161B7592A8C0E799BC49D80B5" +
				"D41882E8D39349CBBB7A69F6A15DBC18C810F25526C3FDBD6EACFD1EB20F06E6" +
				"BEED8ACB9AC00E3064E0DEC74A4F8F64E0DCC467A2B3B98F69B9108327E18692" +
				"ECB6DBDE7C74696BCF4CE8F5B355DE0F01000401010007FF:dn",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			t.Parallel()

			keyCred, err := keycred.ParseDNWithBinary(testCase.DNWithBinary)
			if err != nil {
				t.Fatalf("parse DN with binary: %v", err)
			}

			err = keyCred.Validate()
			if err != nil {
				t.Errorf("normal validation failed: %v", err)
			}

			err = keyCred.ValidateStrict()
			if err == nil {
				t.Errorf("strict validation of test case %q did not return an error", testCase.TestName)
			}

			if keyCred.DNWithBinary() != testCase.DNWithBinary {
				t.Errorf("DNWithBinary changed")
			}
		})
	}
}

func TestValidatedWriteCompatbile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		TestName                 string
		DNWithBinary             string
		ValidatedWriteCompatible bool
	}{
		{
			TestName: "keycred.GeneratePFXAndKeyCredentialLink",
			DNWithBinary: "B:572:0002000020000187F7A47F027D368DC353D1E7C2007E08B6" +
				"923A58575785D1380467BB2DAC5601200002091BD2C41D351D6B021163029BCC" +
				"235E81FA3F1A371C3C80A7448C3788B3AF609B00035253413100040000030000" +
				"00800000000000000000000000010001A6D6174F2A744130972E0B6DF0147837" +
				"B8452832E23847C3FD264392816DD9AB612E3696000B893790AB8D17CCABEC7F" +
				"49140817EF59630AD03851764E9354F786D2F82A89BCBF90093B17C5D3197671" +
				"8869A3FEF08764C1D612964A6D9E2FBE3824C904ECB99119E1806350E97A72FF" +
				"781C5039C0035D1941BA6652CCE67FE901000401010005001000063C04FB3CCC" +
				"F747EA94DB96AF282D893002000701000800085AC1DEA6924FDB0108000977C1" +
				"DEA6924FDB01:dn",
			ValidatedWriteCompatible: false,
		},
		// TODO: update these tests with new requirements
		// {
		// 	TestName: "keycred.GeneratePFXAndValidatedWriteCompatibleKeyCredentialLink",
		// 	DNWithBinary: "B:510:000200002000017F4BD988C7FA085A502DA0FDDBD174924E" +
		// 		"11D025E08267D11FF94125FCEAB5C1200002DF92D0DCC793FE1B17899688E34D" +
		// 		"8F4D061AAE3285D23CECA21EB8CC08BF28B78C000330818902818100A55A1E44" +
		// 		"4D810F735E5B32D027D7764727C26E288A2458EEAE1BEDAEF9312AE2CE2E2C48" +
		// 		"BFA54BBD73A81B7D73060E70AB33D677C3AE7A1F74EA4811CE019B0B766B03E2" +
		// 		"9314E290F9606DD7657304D44003B49A5116820F384B803D85DAC097ECE8BE61" +
		// 		"E9EA57C04505655C2A9AC6F876206041D5839C5B2DAFA5612EA1809F02030100" +
		// 		"0101000401010005001000068A408078F01546E48B4AD57B0E37088F08000934" +
		// 		"E614EC924FDB01:dn",
		// 	ValidatedWriteCompatible: true,
		// },
		// {
		// 	TestName: "keycred.GeneratePFXAndValidatedWriteCompatibleKeyCredentialLink" +
		// 		" with non-DER key material",
		// 	DNWithBinary: "B:540:000200002000016E11FBFF7308114B70C4EE5C7D4A9F7B73" +
		// 		"B821A4DAA10D1977207564501F29A920000236FF92E04FB095C118B75D05D5C3" +
		// 		"8C392389F6F9F2C2D477CE534768E97E673C9B00035253413100040000030000" +
		// 		"00800000000000000000000000010001BBEFCD928D80883C3EE96E3916CF5FB9" +
		// 		"809A0502518186C781310C729B9B127C9F0EF4C5F29797C759ABA8291DB066A5" +
		// 		"0B10807DC6E3A1A237C510BF44D826221ACD84BF88C580F76187DF27D2A70284" +
		// 		"E7A7DB4E0829FBCDED9128281747BD07EC9F0F03E3010CABD0156660CA5F28DA" +
		// 		"469A7043B987A71F930A21CDD1BFD1450100040101000500100006B9EE0A61E6" +
		// 		"85465B892ADFF5D557DED2080009F435D1B79E4FDB01:dn",
		// 	ValidatedWriteCompatible: true,
		// },
		{
			TestName: "key source Entra ID",
			DNWithBinary: "B:510:000200002000018F54D452C9890AF4CA9FA073075657135D" +
				"4B376F08346D73548A4095422C4CE32000024A47385548A97E40CED251131E1A" +
				"6A488DDA43A37F2FAF8D4C4DE796435442418C000330818902818100E943AF39" +
				"AD0739FE146D7AF5FC980BD5A24ED330C81291F9C216ABB8AF2C36CF33F95D8F" +
				"6012BE6BEA3EF637C21ED1A410744DE4A1CA9D209AF502E88B2AADE0F50A9877" +
				"730EF9863541419439A2469C43E305327D24F080116D828A0CE111877CD15142" +
				"9C6CB50CC2452CD91C1EF4D70B3E90B25E09D1653BD3F56F0DCBF15D02030100" +
				"010100040101000501100006284A5EB8A16142D39F4ECE42458D5ABE080009E2" +
				"DF5B7F9E4FDB01:dn",
			ValidatedWriteCompatible: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			t.Parallel()

			keyCred, err := keycred.ParseDNWithBinary(testCase.DNWithBinary)
			if err != nil {
				t.Fatalf("parse DN with binary: %v", err)
			}

			err = keyCred.CheckValidatedWriteCompatible()

			switch {
			case testCase.ValidatedWriteCompatible && err != nil:
				t.Errorf("test case %q should be validated write compatible but check reports: %v",
					testCase.TestName, err)
			case !testCase.ValidatedWriteCompatible && err == nil:
				t.Errorf("test case %q should not be validated write compatible but check claims it is",
					testCase.TestName)
			}
		})
	}
}

func TestRemove(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	lastLogon := time.Now()

	additionalProperties := []keycred.KeyCredentialLinkEntry{
		keycred.NewKeySourceEntry(keycred.KeySourceAD),
		keycred.NewKeyApproximateLastLogonTimeStampEntry(lastLogon),
	}

	kcl, err := keycred.NewKeyCredentialLink(
		&key.PublicKey, "CN=Administrator,CN=Users,DC=lab,DC=redteam", keycred.KeyUsageNGC, additionalProperties...)
	if err != nil {
		t.Fatalf("generate KeyCredentialLink: %v", err)
	}

	if kcl.Remove(keycred.TypeDeviceId) {
		t.Fatalf("trying to remove non-existing device type entry did not return false")
	}

	if kcl.Index(keycred.TypeKeyApproximateLastLogonTimeStamp) < 0 {
		t.Fatalf("last logon time stamp was not present before removal")
	}

	if !kcl.Remove(keycred.TypeKeyApproximateLastLogonTimeStamp) {
		t.Fatalf("removing last logon time stamp did not return true")
	}

	err = kcl.ValidateStrict()
	if err != nil {
		t.Fatalf("validation failed after removing last logon time stamp: %v", err)
	}

	if kcl.Index(keycred.TypeKeyApproximateLastLogonTimeStamp) >= 0 {
		t.Fatalf("last logon time stamp is still present after removal")
	}
}

func TestSort(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyMaterialEntry, err := keycred.NewKeyMaterialEntry(&key.PublicKey, true, keycred.Version2)
	if err != nil {
		t.Fatalf("generate key material entry: %v", err)
	}

	keyIDEntry, err := keycred.NewKeyIDEntry(keyMaterialEntry, keycred.Version2)
	if err != nil {
		t.Fatalf("generate key ID entry: %v", err)
	}

	unknownEntry := &keycred.RawEntry{}

	kcl := &keycred.KeyCredentialLink{
		Version: keycred.Version2,
		Entries: []keycred.KeyCredentialLinkEntry{
			unknownEntry,
			keycred.NewKeyCreationTimeEntry(time.Now()),
			keycred.NewKeyApproximateLastLogonTimeStampEntry(time.Now()),
			keycred.NewCustomKeyInformationEntry(&keycred.CustomKeyInformation{}),
			keycred.NewDeviceIDEntry(uuid.New()),
			keycred.NewKeySourceEntry(keycred.KeySourceAD),
			keycred.NewKeyUsageEntry(keycred.KeyUsageNGC),
			keyMaterialEntry,
			keycred.NewKeyHashEntry([]keycred.KeyCredentialLinkEntry{keyIDEntry}),
			keyIDEntry,
		},
	}

	if kcl.Sorted() {
		t.Fatalf("Sort() claims that unsorted KCL is sorted")
	}

	kcl.Sort()

	if !kcl.Sorted() {
		t.Fatalf("KCL is not sorted after sorting")
	}

	if kcl.Entries[len(kcl.Entries)-1] != unknownEntry {
		t.Fatalf("unknown entry was not placed at the end")
	}

	err = kcl.Validate()
	if err != nil {
		t.Fatalf("validate sorted KCL: %v", err)
	}
}

func TestMakeValidatedWriteCompatible(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	kcl, err := keycred.NewKeyCredentialLink(
		&key.PublicKey,
		"",
		keycred.KeyUsageAdminKey,
		keycred.NewKeyApproximateLastLogonTimeStampEntry(time.Now()),
		keycred.NewKeySourceEntry(keycred.KeySourceEntraID),
		keycred.NewCustomKeyInformationEntry(&keycred.CustomKeyInformation{}),
	)
	if err != nil {
		t.Fatalf("generate non-validated-write compatible KeyCredentialLink: %v", err)
	}

	err = kcl.CheckValidatedWriteCompatibleStrict()
	if err == nil {
		t.Fatalf("KeyCredentialLink is already validated write compatible")
	}

	kcl, err = keycred.MakeValidatedWriteCompatible(kcl)
	if err != nil {
		t.Fatalf("MakeValidatedWriteCompatible: %v", err)
	}

	err = kcl.CheckValidatedWriteCompatibleStrict()
	if err != nil {
		t.Fatalf("KeyCredentialLink is not validated write compatible after modification")
	}
}
