package app

import "forward/internal/config"

func setupManagedTProxyRules(cfg config.Config) (func(), error) {
	if !shouldManageTProxyRules(cfg) {
		return func() {}, nil
	}
	return setupManagedTProxyRulesPlatform(cfg)
}

func shouldManageTProxyRules(cfg config.Config) bool {
	return cfg.TProxy != nil
}
