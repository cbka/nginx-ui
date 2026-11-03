package kernel

import (
	"context"

	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/query"
	"github.com/uozi-tech/cosy/logger"
)

func RegisterAcmeUser(ctx context.Context) {
	a := query.AcmeUser
	users, err := a.Where(a.RegisterOnStartup.Is(true)).Find()
	if err != nil {
		logger.Error(err)
		return
	}
	for _, user := range users {
		err := registerStartupAccount(user, (*model.AcmeUser).Register, func(candidate *model.AcmeUser) error {
			_, err := a.Where(a.ID.Eq(candidate.ID)).Updates(candidate)
			return err
		})
		if err != nil {
			logger.Error(err)
		}
	}
}

func registerStartupAccount(user *model.AcmeUser, register func(*model.AcmeUser) error, save func(*model.AcmeUser) error) error {
	if user.HasAccountIdentity() {
		return nil
	}
	if err := register(user); err != nil {
		return err
	}
	return save(user)
}
