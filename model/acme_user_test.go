package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestRegisterFailurePreservesAccountIdentity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user := AcmeUser{Email: "test@example.invalid", CADir: "https://ca.example.invalid/directory", Proxy: "://invalid", Registration: AcmeRegistration{URI: "https://ca.example.invalid/account/1"}, Key: PrivateKey{X: key.X, Y: key.Y, D: key.D}}
	before := user
	if err := user.Register(); err == nil {
		t.Fatal("invalid proxy must fail before network access")
	}
	if user.Registration.URI != before.Registration.URI || user.Key.X != before.Key.X || user.Key.Y != before.Key.Y || user.Key.D != before.Key.D {
		t.Fatal("failed registration changed original account identity")
	}
	if !user.HasAccountIdentity() {
		t.Fatal("valid identity not recognized")
	}
	user.Key.D = nil
	if user.HasAccountIdentity() {
		t.Fatal("missing private key accepted")
	}
}
