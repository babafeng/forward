package app

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"forward/base/endpoint"
	"forward/internal/config"
	"forward/internal/router"
)

type routerCache struct {
	mu      sync.Mutex
	entries map[string]*routerCacheEntry
}

type routerCacheEntry struct {
	once sync.Once
	rt   router.Router
	err  error
}

func newRouterCache() *routerCache {
	return &routerCache{
		entries: make(map[string]*routerCacheEntry),
	}
}

func (c *routerCache) getOrBuild(cfg config.Config) (router.Router, error) {
	if c == nil {
		return buildRouter(cfg)
	}

	key := routerCacheKey(cfg)

	c.mu.Lock()
	entry := c.entries[key]
	if entry == nil {
		entry = &routerCacheEntry{}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		entry.rt, entry.err = buildRouter(cfg)
	})

	if entry.err != nil {
		// Keep failures retryable; subscription downloads and route parsing may
		// transiently fail during startup.
		c.mu.Lock()
		if c.entries[key] == entry {
			delete(c.entries, key)
		}
		c.mu.Unlock()
	}

	return entry.rt, entry.err
}

func routerCacheKey(cfg config.Config) string {
	var b strings.Builder

	writeCacheField(&b, "node", cfg.NodeName)
	writeCacheField(&b, "dial_timeout", cfg.DialTimeout.String())
	writeCacheField(&b, "subscribe_filter", cfg.SubscribeFilter)
	writeCacheField(&b, "subscribe_update", strconv.Itoa(cfg.SubscribeUpdate))
	writeCacheField(&b, "route_store", fmt.Sprintf("%p", cfg.RouteStore))
	writeCacheField(&b, "route_config", fmt.Sprintf("%p", cfg.Route))

	for _, raw := range cfg.EffectiveSubscribeURLs() {
		writeCacheField(&b, "subscribe_url", raw)
	}

	if cfg.Forward != nil {
		writeCacheField(&b, "forward", endpointCacheKey(*cfg.Forward))
	}
	for _, hop := range cfg.ForwardChain {
		writeCacheField(&b, "forward_chain", endpointCacheKey(hop))
	}

	return b.String()
}

func writeCacheField(b *strings.Builder, key, value string) {
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(value)
	b.WriteByte('\n')
}

func endpointCacheKey(ep endpoint.Endpoint) string {
	var b strings.Builder

	b.WriteString(strings.ToLower(strings.TrimSpace(ep.Scheme)))
	b.WriteByte('|')
	b.WriteString(ep.Host)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(ep.Port))
	b.WriteByte('|')
	b.WriteString(ep.Path)
	b.WriteByte('|')
	b.WriteString(ep.RAddress)
	b.WriteByte('|')
	b.WriteString(ep.FAddress)

	if ep.User != nil {
		b.WriteString("|user=")
		b.WriteString(ep.User.Username())
		if pass, ok := ep.User.Password(); ok {
			b.WriteByte(':')
			b.WriteString(pass)
		}
	}
	if len(ep.Query) > 0 {
		b.WriteString("|query=")
		b.WriteString(ep.Query.Encode())
	}

	return b.String()
}
