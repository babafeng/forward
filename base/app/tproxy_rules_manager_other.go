//go:build !linux

package app

import "forward/internal/config"

func setupManagedTProxyRulesPlatform(cfg config.Config) (func(), error) {
	if cfg.Logger != nil {
		cfg.Logger.Info("Skip managed tproxy rules on non-Linux platform")
	}
	return func() {}, nil
}
