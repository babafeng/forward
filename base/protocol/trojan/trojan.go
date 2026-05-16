// Package trojan provides small helpers for Trojan account handling.
package trojan

import (
	"fmt"

	"github.com/xtls/xray-core/common/protocol"
	xtrojan "github.com/xtls/xray-core/proxy/trojan"
)

func CreateUser(password string) (*protocol.MemoryUser, error) {
	if password == "" {
		return nil, fmt.Errorf("trojan password is required")
	}
	account, err := (&xtrojan.Account{Password: password}).AsAccount()
	if err != nil {
		return nil, err
	}
	return &protocol.MemoryUser{Account: account}, nil
}

func CreateValidator(password string) (*xtrojan.Validator, error) {
	user, err := CreateUser(password)
	if err != nil {
		return nil, err
	}
	validator := new(xtrojan.Validator)
	if err := validator.Add(user); err != nil {
		return nil, err
	}
	return validator, nil
}
