package keycred_test

import (
	"testing"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/keycred"
)

func TestGeneratePFXAndKeyCredentialLink(t *testing.T) {
	t.Parallel()

	keySize := 1024

	t.Run("unencrypted", func(t *testing.T) {
		t.Parallel()

		keyCred, err := keycred.GeneratePFXAndKeyCredentialLink(
			keySize,
			"user1",
			"CN=user,DC=domain",
			"",
			[16]byte(make([]byte, 16)),
			"",
		)
		if err != nil {
			t.Fatalf("generate KeyCredentialLink without password: %v", err)
		}

		if keyCred.Key.Size()*8 != keySize {
			t.Fatalf("key size is %d instead of %d", keyCred.Key.Size()*8, keySize)
		}

		_, _, _, err = adauth.DecodePFX(keyCred.PFX, "")
		if err != nil {
			t.Fatalf("unencrypted PFX cannot be decoded: %v", err)
		}
	})

	t.Run("encrypted", func(t *testing.T) {
		t.Parallel()

		password := "hunter2"

		keyCred, err := keycred.GeneratePFXAndKeyCredentialLink(
			keySize,
			"user1",
			"CN=user,DC=domain",
			"",
			[16]byte(make([]byte, 16)),
			password,
		)
		if err != nil {
			t.Fatalf("generate KeyCredentialLink with password: %v", err)
		}

		if keyCred.Key.Size()*8 != keySize {
			t.Fatalf("key size is %d instead of %d", keyCred.Key.Size()*8, keySize)
		}

		_, _, _, err = adauth.DecodePFX(keyCred.PFX, password)
		if err != nil {
			t.Fatalf("encrypted PFX cannot be decoded: %v", err)
		}
	})
}

func TestGeneratePFXAndValidatedWriteCompatibleKeyCredentialLink(t *testing.T) {
	t.Parallel()

	keySize := 1024

	t.Run("unencrypted", func(t *testing.T) {
		t.Parallel()

		keyCred, err := keycred.GeneratePFXAndValidatedWriteCompatibleKeyCredentialLink(
			keySize,
			"user1",
			"CN=user,DC=domain",
			"",
			[16]byte(make([]byte, 16)),
			"",
		)
		if err != nil {
			t.Fatalf("generate KeyCredentialLink without password: %v", err)
		}

		err = keyCred.KeyCredentialLink.ValidateStrict()
		if err != nil {
			t.Fatalf("ValidateStrict failed: %v", err)
		}

		err = keyCred.KeyCredentialLink.CheckValidatedWriteCompatible()
		if err != nil {
			t.Fatalf("CheckValidatedWriteCompatible failed: %v", err)
		}

		if keyCred.Key.Size()*8 != keySize {
			t.Fatalf("key size is %d instead of %d", keyCred.Key.Size()*8, keySize)
		}

		_, _, _, err = adauth.DecodePFX(keyCred.PFX, "")
		if err != nil {
			t.Fatalf("unencrypted PFX cannot be decoded: %v", err)
		}
	})

	t.Run("encrypted", func(t *testing.T) {
		t.Parallel()

		password := "hunter2"

		keyCred, err := keycred.GeneratePFXAndValidatedWriteCompatibleKeyCredentialLink(
			keySize,
			"user1",
			"CN=user,DC=domain",
			"",
			[16]byte(make([]byte, 16)),
			password,
		)
		if err != nil {
			t.Fatalf("generate KeyCredentialLink with password: %v", err)
		}

		err = keyCred.KeyCredentialLink.ValidateStrict()
		if err != nil {
			t.Fatalf("ValidateStrict failed: %v", err)
		}

		err = keyCred.KeyCredentialLink.CheckValidatedWriteCompatible()
		if err != nil {
			t.Fatalf("CheckValidatedWriteCompatible failed: %v", err)
		}

		if keyCred.Key.Size()*8 != keySize {
			t.Fatalf("key size is %d instead of %d", keyCred.Key.Size()*8, keySize)
		}

		_, _, _, err = adauth.DecodePFX(keyCred.PFX, password)
		if err != nil {
			t.Fatalf("encrypted PFX cannot be decoded: %v", err)
		}
	})
}
