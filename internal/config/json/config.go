package json

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"forward/base/endpoint"
	"forward/base/logging"
	"forward/internal/config"
)

const configFileName = "forward.json"

func DefaultConfigPaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get user home dir: %w", err)
	}
	return []string{
		filepath.Join(home, ".forward", configFileName),
		filepath.Join(home, configFileName),
	}, nil
}

func FindDefaultConfig() (string, error) {
	paths, err := DefaultConfigPaths()
	if err != nil {
		return "", err
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("Config File %s Not Found in %s", configFileName, strings.Join(paths, " "))
}

type NodeFileConfig struct {
	Name      string   `json:"name"`
	Listeners []string `json:"listeners"`
	Listen    string   `json:"listen,omitempty"`
	Forward   string   `json:"forward,omitempty"`
	Forwards  []string `json:"forwards,omitempty"`
	Insecure  bool     `json:"insecure,omitempty"`
}

type FileConfig struct {
	Nodes     []NodeFileConfig `json:"nodes,omitempty"`
	Listeners []string         `json:"listeners,omitempty"`
	Listen    string           `json:"listen,omitempty"`
	Forward   string           `json:"forward,omitempty"`
	Forwards  []string         `json:"forwards,omitempty"`
	Insecure  bool             `json:"insecure,omitempty"`
	Debug     bool             `json:"debug,omitempty"`
}

func ParseFile(path string) (config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config.Config{}, fmt.Errorf("read config file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (config.Config, error) {
	var fc FileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return config.Config{}, fmt.Errorf("parse json: %w", err)
	}
	return fc.ToConfig()
}

func (fc *FileConfig) ToConfig() (config.Config, error) {
	cfg := config.Config{}

	logLevel := "info"
	if fc.Debug {
		logLevel = "debug"
	}
	llevel, err := logging.ParseLevel(logLevel)
	if err != nil {
		return config.Config{}, err
	}
	cfg.Logger = logging.New(logging.Options{Level: llevel})
	cfg.LogLevel = llevel

	if len(fc.Nodes) > 0 {
		for i, n := range fc.Nodes {
			node, err := parseNode(n, i)
			if err != nil {
				return cfg, err
			}
			cfg.Nodes = append(cfg.Nodes, node)
		}
		config.ApplyDefaults(&cfg)
		return cfg, nil
	}

	if len(fc.Listeners) == 0 && fc.Listen == "" {
		return cfg, fmt.Errorf("listeners or listen is required")
	}

	node, err := parseNode(NodeFileConfig{
		Name:      "default",
		Listeners: fc.Listeners,
		Listen:    fc.Listen,
		Forward:   fc.Forward,
		Forwards:  fc.Forwards,
		Insecure:  fc.Insecure,
	}, 0)
	if err != nil {
		return cfg, err
	}
	cfg.Nodes = []config.NodeConfig{node}

	cfg.Listeners = node.Listeners
	cfg.Listen = node.Listeners[0]
	cfg.Forward = node.Forward
	cfg.ForwardChain = node.ForwardChain
	cfg.Insecure = node.Insecure

	config.ApplyDefaults(&cfg)
	return cfg, nil
}

func parseNode(n NodeFileConfig, index int) (config.NodeConfig, error) {
	node := config.NodeConfig{
		Name:     n.Name,
		Insecure: n.Insecure,
	}
	if node.Name == "" {
		node.Name = fmt.Sprintf("node_%d", index)
	}

	if len(n.Listeners) == 0 && n.Listen == "" {
		return node, fmt.Errorf("node %s: listeners or listen is required", node.Name)
	}

	if n.Listen != "" {
		ep, err := endpoint.Parse(n.Listen)
		if err != nil {
			return node, fmt.Errorf("node %s: parse listen: %w", node.Name, err)
		}
		node.Listeners = append(node.Listeners, ep)
	}

	for _, l := range n.Listeners {
		ep, err := endpoint.Parse(l)
		if err != nil {
			return node, fmt.Errorf("node %s: parse listener %s: %w", node.Name, l, err)
		}
		node.Listeners = append(node.Listeners, ep)
	}

	if strings.TrimSpace(n.Forward) != "" && len(n.Forwards) > 0 {
		return node, fmt.Errorf("node %s: forward and forwards are mutually exclusive", node.Name)
	}

	if len(n.Forwards) > 0 {
		for _, raw := range n.Forwards {
			ef, err := endpoint.Parse(raw)
			if err != nil {
				return node, fmt.Errorf("node %s: parse forward %s: %w", node.Name, raw, err)
			}
			node.ForwardChain = append(node.ForwardChain, ef)
		}
		if len(node.ForwardChain) > 0 {
			last := node.ForwardChain[len(node.ForwardChain)-1]
			node.Forward = &last
		}
	} else if strings.TrimSpace(n.Forward) != "" {
		ef, err := endpoint.Parse(n.Forward)
		if err != nil {
			return node, fmt.Errorf("node %s: parse forward: %w", node.Name, err)
		}
		node.Forward = &ef
		node.ForwardChain = []endpoint.Endpoint{ef}
	}

	return node, nil
}
