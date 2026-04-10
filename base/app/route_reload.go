package app

import (
	"context"
	"hash/fnv"
	"os"
	"strings"
	"time"

	"forward/base/route"
	"forward/internal/config"
)

type routeFileState struct {
	modTimeUnixNano int64
	size            int64
	checksum        uint64
}

func initRouteStoreAndHotReload(ctx context.Context, cfg *config.Config) error {
	if cfg == nil || cfg.Route == nil {
		return nil
	}
	if cfg.RouteStore == nil {
		store, err := route.NewStore(cfg.Route, cfg.Logger)
		if err != nil {
			return err
		}
		cfg.RouteStore = store
	}
	path := strings.TrimSpace(cfg.RoutePath)
	if path == "" {
		return nil
	}
	var initialState *routeFileState
	if state, err := readRouteFileState(path); err == nil {
		initialState = &state
	}
	go watchRouteConfig(ctx, cfg, initialState)
	return nil
}

func watchRouteConfig(ctx context.Context, cfg *config.Config, initialState *routeFileState) {
	if cfg == nil || cfg.RouteStore == nil {
		return
	}
	path := strings.TrimSpace(cfg.RoutePath)
	if path == "" {
		return
	}

	lastState := routeFileState{}
	hasState := false
	lastStatErr := ""
	if initialState != nil {
		lastState = *initialState
		hasState = true
	} else if state, err := readRouteFileState(path); err == nil {
		lastState = state
		hasState = true
	} else {
		lastStatErr = err.Error()
		if cfg.Logger != nil {
			cfg.Logger.Warn("Route hot reload stat %s failed: %v", path, err)
		}
	}

	if cfg.Logger != nil {
		cfg.Logger.Info("Route hot reload enabled: %s (poll: 5s)", path)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state, err := readRouteFileState(path)
			if err != nil {
				if cfg.Logger != nil {
					msg := err.Error()
					if msg != lastStatErr {
						cfg.Logger.Warn("Route hot reload stat %s failed: %v", path, err)
						lastStatErr = msg
					}
				}
				continue
			}
			lastStatErr = ""
			if hasState && state == lastState {
				continue
			}

			routeCfg, err := parseRouteConfig(path)
			// Parse/update errors should not break serving. Keep current route and wait for next file change.
			if err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Warn("Route hot reload parse %s failed: %v", path, err)
				}
				lastState = state
				hasState = true
				continue
			}
			if routeCfg.Route == nil {
				if cfg.Logger != nil {
					cfg.Logger.Warn("Route hot reload skipped: no route config in %s", path)
				}
				lastState = state
				hasState = true
				continue
			}
			if err := cfg.RouteStore.Update(routeCfg.Route, cfg.Logger); err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Warn("Route hot reload update %s failed: %v", path, err)
				}
				lastState = state
				hasState = true
				continue
			}

			lastState = state
			hasState = true
			if cfg.Logger != nil {
				cfg.Logger.Info("Route config reloaded from %s (version=%d)", path, cfg.RouteStore.Version())
			}
		}
	}
}

func readRouteFileState(path string) (routeFileState, error) {
	info, err := os.Stat(path)
	if err != nil {
		return routeFileState{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return routeFileState{}, err
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write(content)
	return routeFileState{
		modTimeUnixNano: info.ModTime().UnixNano(),
		size:            info.Size(),
		checksum:        hasher.Sum64(),
	}, nil
}
