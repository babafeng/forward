package utils

import "sync/atomic"

var (
	insecureSkipVerify atomic.Bool
)

func SetInsecure(insecure bool) {
	insecureSkipVerify.Store(insecure)
}

func GetInsecure() bool {
	return insecureSkipVerify.Load()
}
