package keycred

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type fidoAuthData struct {
	RPIDHash  [32]byte
	Flags     fidoAuthDataFlag
	SignCount uint32
	// the attestedCredentialData and extension can currently not be parsed
	// completely.
	attestedCredentialData *attestedCredentialData
}

type fidoAuthDataFlag uint8

const (
	fidoAuthDataFlagUserPresent                        fidoAuthDataFlag = 0
	fidoAuthDataFlagUserVerified                       fidoAuthDataFlag = 2
	fidoAuthDataFlagUserAttestedCredentialDataIncluded fidoAuthDataFlag = 6
	fidoAuthDataFlagUserExtensionDataIncluded          fidoAuthDataFlag = 7
)

func parseFIDOAuthData(data []byte) (fad *fidoAuthData, err error) {
	consumer := newConsumer(data, binary.BigEndian)

	fad = &fidoAuthData{
		RPIDHash:  [32]byte(consumer.Bytes(32)),
		Flags:     fidoAuthDataFlag(consumer.Uint8()),
		SignCount: consumer.Uint32(),
	}

	remaininBytes := consumer.Bytes(consumer.Remaining())

	if consumer.Error() != nil {
		return nil, consumer.Error()
	}

	consumer = newConsumer(remaininBytes, binary.BigEndian)

	if fad.Flags&fidoAuthDataFlagUserAttestedCredentialDataIncluded > 0 {
		acd := &attestedCredentialData{}

		acd.AAGUID, err = uuid.FromBytes(consumer.Bytes(16))
		if err != nil {
			return nil, fmt.Errorf("parse AAGUID in attested credential data: %w", err)
		}

		acd.CredentialLength = consumer.Uint16()
		acd.CredentialID = consumer.Bytes(int(acd.CredentialLength))

		// the public key can currently not be parsed
		fad.attestedCredentialData = acd
	}

	// without parsing the public key, the size of the credential data cannot be
	// determined and it is not possible to know were the extensions start
	_ = consumer.Bytes(consumer.Remaining())

	if consumer.Error() != nil {
		return nil, fmt.Errorf("parse attested credential data: %w", consumer.Error())
	}

	return fad, nil
}

type attestedCredentialData struct {
	AAGUID           uuid.UUID
	CredentialLength uint16
	CredentialID     []byte
}

//nolint:gocyclo
func humanReadableAADGUI(aadgui uuid.UUID) string {
	switch strings.ToLower(aadgui.String()) {
	case "de1e552d-db1d-4423-a619-566b625cdc84":
		return "Microsoft Authenticator for Android"
	case "90a3ccdf-635c-4729-a248-9b709135078f":
		return "Microsoft Authenticator for iOS"
	case "fcb1bcb4-f370-078c-6993-bc24d0ae3fbe":
		return "Ledger Nano X FIDO2 Authenticator"
	case "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4":
		return "Google Password Manager"
	case "adce0002-35bc-c60a-648b-0b25f1f05503":
		return "Chrome on Mac"
	case "08987058-cadc-4b81-b6e1-30de50dcbe96", "9ddd1817-af5a-4672-a2b9-3e3dd95000a9",
		"6028b017-b1d4-4c02-b4b3-afcdafc96bb2":
		return "Windows Hello"
	case "dd4ec289-e01d-41c9-bb89-70fa845d4bf2":
		return "iCloud Keychain (Managed)"
	case "fbfc3007-154e-4ecc-8c0b-6e020557d7bd":
		return "iCloud Keychain"
	case "531126d6-e717-415c-9320-3d9aa6981239":
		return "Dashlane"
	case "bada5566-a7aa-401f-bd96-45619a55120d":
		return "1Password"
	case "b84e4048-15dc-4dd0-8640-f4f60813c8af":
		return "NorthPass"
	case "0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6":
		return "Keeper"
	case "891494da-2c90-4d31-a9cd-4eab0aed1309":
		return "Sésame"
	case "f3809540-7f14-49c1-a8b3-8f813b225541":
		return "Enpass"
	case "b5397666-4885-aa6b-cebf-e52262a439a2":
		return "Chromium Browser"
	case "771b48fd-d3d4-4f74-9232-fc157ab0507a":
		return "Edge on Mac"
	case "39a5647e-1853-446c-a1f6-a79bae9f5bc7":
		return "IDmelon"
	case "d548826e-79b4-db40-a3d8-11116f7e8349":
		return "Birwarden"
	case "53414d53-554e-4700-0000-000000000000":
		return "Samsung Pass"
	case "66a0ccb3-bd6a-191f-ee06-e375c50b9846", "8836336a-f590-0921-301d-46427531eee6":
		return "Thales Bio iOS SDK"
	case "cd69adb5-3c7a-deb9-3177-6800ea6cb72a", "17290f1e-c212-34d0-1423-365d729f09d9":
		return "Thales PIN Android SDK"
	case "50726f74-6f6e-5061-7373-50726f746f6e":
		return "Proton Pass"
	case "fdb141b2-5d84-443e-8a35-4698c205a502":
		return "KeePassXC"
	case "cc45f64e-52a2-451b-831a-4edd8022a202":
		return "ToothPic Passkey Provider"
	case "bfc748bb-3429-4faa-b9f9-7cfa9f3b76d0":
		return "iPasswords"
	case "b35a26b2-8f6e-4697-ab1d-d44db4da28c6":
		return "Zoho Vault"
	case "b78a0a55-6ef8-d246-a042-ba0f6d55050c":
		return "LastPass"
	case "de503f9c-21a4-4f76-b4b7-558eb55c6f89":
		return "Devolutions"
	case "22248c4c-7a12-46e2-9a41-44291b373a4d":
		return "LogMeOnce"
	case "a10c6dd9-465e-4226-8198-c7c44b91c555":
		return "Kaspersky Password Manager"
	case "cb69481e-8ff7-4039-93ec-0a2729a154a8":
		return "YubiKey 5/5C/5 Nano (Firmware 5.1, Level 1)"
	case "ee882879-721c-4913-9775-3dfcce97072a":
		return "YubiKey 5/5C/5 Nano (Firmware 5.2/5.4, Level 1)"
	case "fa2b99dc-9e39-4257-8f92-4a30d23c4118":
		return "YubiKey 5 NFC (Firmware 5.1, Level 1)"
	case "2fc0579f-8113-47ea-b116-bb5a8db9202a":
		return "YubiKey 5/5C NFC (Firmware 5.2/5.4, Level 1)"
	case "a25342c0-3cdc-4414-8e46-f4807fca511c", "d7781e5d-e353-46aa-afe2-3ca49f13332a":
		return "YubiKey 5/5C NFC (Firmware 5.7, Level 2)"
	case "19083c3d-8383-4b18-bc03-8f1c9ab2fd1b", "ff4dac45-ede8-4ec2-aced-cf66103f4335":
		return "YubiKey 5C / 5C Nano (Firmware 5.7, Level 2)"
	case "c5ef55ff-ad9a-4b9f-b580-adebafe026d0":
		return "YubiKey 5Ci (Firmware 5.2/5.4, Level 1)"
	case "a02167b9-ae71-4ac7-9a07-06432ebb6f1c ", "24673149-6c86-42e7-98d9-433fb5b73296":
		return "YubiKey 5Ci (Firmware 5.7, Level 2)"
	case "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd":
		return "YubiKey 5/5C NFC FIPS (Firmware 5.4, Level 2)"
	case "73bb0cd4-e502-49b8-9c6f-b59445bf720b":
		return "YubiKey 5/5C/5C Nano FIPS (Firmware 5.4, Level 2)"
	case "85203421-48f9-4355-9bc8-8a53846e5083":
		return "YubiKey 5Ci FIPS (Firmware 5.4, Level 2)"
	case "fcc0118f-cd45-435b-8da1-9782b2da0715":
		return "YubiKey 5/5C NFC FIPS RC (Firmware 5.7, Level 2)"
	case "57f7de54-c807-4eab-b1c6-1c9be7984e92":
		return "YubiKey 5C/5 Nano/5C Nano FIPS RC (Firmware 5.7, Level 2)"
	case "7b96457d-e3cd-432b-9ceb-c9fdd7ef7432":
		return "YubiKey 5Ci FIPS RC (Firmware 5.7, Level 2)"
	case "d8522d9f-575b-4866-88a9-ba99fa02f35b":
		return "YubiKey Bio - FIDO Edition (Firmware 5.5/5.6, Level 1)"
	case "dd86a2da-86a0-4cbe-b462-4bd31f57bc6f", "7409272d-1ff9-4e10-9fc9-ac0019c124fd":
		return "YubiKey Bio - FIDO Edition (Firmware 5.7, Level 2)"
	case "7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3":
		return "YubiKey Bio Series - Multi-protocol Edition (Firmware 5.6, Level 1)"
	case "90636e1f-ef82-43bf-bdcf-5255f139d12f", "34744913-4f57-4e6e-a527-e9ec3c4b94e6":
		return "YubiKey Bio Series - Multi-protocol Edition (Firmware 5.7, Level 2)"
	case "f8a011f3-8c0a-4d15-8006-17111f9edc7d":
		return "Security Key By Yubico (Blue) (Firmware 5.1, Level 1)"
	case "b92c3f9a-c014-4056-887f-140a2501163b":
		return "Security Key By Yubico (Blue) (Firmware 5.2, Level 1)"
	case "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73":
		return "Security Key NFC (Blue) (Firmware 5.1, Level 1)"
	case "149a2021-8ef6-4133-96b8-81f8d5b7f1f5":
		return "Security Key NFC (USB-A, USB-C) (Blue) (Firmware 5.2/5.4, Level 1)"
	case "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa":
		return "Security Key NFC (Black) (USB-A, USB-C) (Firmware 5.4, Level 2)"
	case "e77e3c64-05e3-428b-8824-0cbeb04b829d", "b7d3f68e-88a6-471e-9ecf-2df26d041ede":
		return "Security Key NFC (Black) (USB-A, USB-C) (Firmware 5.7, Level 2)"
	case "0bb43545-fd2c-4185-87dd-feb0b2916ace":
		return "Security Key NFC - Enterprise Edition (USB-A, USB-C) (Black) (Firmware 5.4, Level 2)"
	case "47ab2fb4-66ac-4184-9ae1-86be814012d5", "ed042a3a-4b22-4455-bb69-a267b652ae7e":
		return "Security Key NFC - Enterprise Edition (USB-A, USB-C) (Black) (Firmware 5.7, Level 2)"
	case "1ac71f64-468d-4fe0-bef1-0e5f2f551f18", "6ab56fad-881f-4a43-acb2-0be065924522":
		return "YubiKey 5/5C NFC (Firmware 5.7, Level 2)"
	case "20ac7a17-c814-4833-93fe-539f0d5e3389", "4599062e-6926-4fe7-9566-9e8fb1aedaa0":
		return "YubiKey 5C/5 Nano/5C Nano (Firmware 5.7, Level 2)"
	case "b90e7dc1-316e-4fee-a25a-56a666a670fe", "3b24bf49-1d45-4484-a917-13175df0867b":
		return "YubiKey 5Ci (Firmware 5.7, Level 2)"
	case "79f3c8ba-9e35-484b-8f47-53a5a0f5c630":
		return "YubiKey 5/5C NFC FIPS (Firmware 5.7, Level 2)"
	case "905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7":
		return "YubiKey 5C/5 Nano/5C Nano FIPS (Firmware 5.7, Level 2)"
	case "3a662962-c6d4-4023-bebb-98ae92e78e20":
		return "YubiKey 5Ci FIPS (Firmware 5.7, Level 2)"
	case "83c47309-aabb-4108-8470-8be838b573cb":
		return "YubiKey Bio Series - FIDO Edition (Firmware 5.6/5.7, Level 1/2)"
	case "ad08c78a-4e41-49b9-86a2-ac15b06899e2":
		return "YubiKey Bio Series - FIDO Edition (Firmware 5.7, Level 2)"
	case "97e6a830-c952-4740-95fc-7c78dc97ce47", "6ec5cff2-a0f9-4169-945b-f33b563f7b99":
		return "YubiKey Bio Series - Multi-protocol Edition (Firmware 5.7, Level 2)"
	case "9ff4cc65-6154-4fff-ba09-9e2af7882ad2", "72c6b72d-8512-4c66-8359-9d3d10d9222f":
		return "Security Key NFC - Enterprise Edition (USB-A, USB-C) (Black) (Firmware 5.7, Level 2)"
	default:
		return fmt.Sprintf("FIDO AADGUI: %s", aadgui)
	}
}
