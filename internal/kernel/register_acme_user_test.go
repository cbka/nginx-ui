package kernel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/0xJacky/Nginx-UI/model"
	"testing"
)

func TestStartupSkipsExistingACMEAccount(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user := &model.AcmeUser{Registration: model.AcmeRegistration{URI: "https://ca.example.invalid/account/1"}, Key: model.PrivateKey{X: key.X, Y: key.Y, D: key.D}, RegisterOnStartup: true}
	forbidden := func(*model.AcmeUser) error {
		t.Fatal("existing identity must not register or save on startup")
		return nil
	}
	if err := registerStartupAccount(user, forbidden, forbidden); err != nil {
		t.Fatal(err)
	}
}

func TestStartupDoesNotSaveFailedACMERegistration(t *testing.T) {
	want := errors.New("registration rejected")
	user := &model.AcmeUser{RegisterOnStartup: true}
	err := registerStartupAccount(user, func(*model.AcmeUser) error { return want }, func(*model.AcmeUser) error { t.Fatal("failed registration must not be saved"); return nil })
	if !errors.Is(err, want) {
		t.Fatal("registration error not returned")
	}
}

func TestStartupPersistsSuccessfulNewACMEAccount(t *testing.T) {
	calls := 0
	user := &model.AcmeUser{RegisterOnStartup: true}
	err := registerStartupAccount(user, func(*model.AcmeUser) error { calls++; return nil }, func(*model.AcmeUser) error { calls++; return nil })
	if err != nil || calls != 2 {
		t.Fatal("new account must register and persist exactly once")
	}
}
