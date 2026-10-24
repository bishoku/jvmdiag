package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	DefaultBaseURL     = "https://openrouter.ai/api"
	DefaultModel       = "openai/gpt-4o"
	DefaultTemperature = 0.3
	DefaultWorkspace   = "default"
)

var ErrInvalidConfig = errors.New("invalid AI configuration")

type AIConfig struct {
	APIKey             string  `json:"apiKey,omitempty"`
	BaseURL            string  `json:"baseUrl"`
	Model              string  `json:"model"`
	Temperature        float64 `json:"temperature"`
	TrustInsecureCerts bool    `json:"trustInsecureCerts"`
}

// Options allows embedding and tests to opt out of ambient configuration sources.
type Options struct {
	SkipDotEnv        bool
	SkipLegacy        bool
	IgnoreEnvironment bool
}

type Manager struct {
	options      Options
	getenv       func(string) string
	mu           sync.RWMutex
	baseDir      string
	globalConfig AIConfig
	wsConfigs    map[string]AIConfig
	matHome      string
	matHeapSize  string
	maxMatMem    string
	multiUser    bool
	maxWorkers   int
}

func NewManager(baseDir string) *Manager { return NewManagerWithOptions(baseDir, Options{}) }

func NewManagerWithOptions(baseDir string, opts Options) *Manager {
	if !opts.SkipDotEnv {
		loadDotEnvFiles(".env", "../.env")
	}
	getenv := os.Getenv
	if opts.IgnoreEnvironment {
		getenv = func(string) string { return "" }
	}
	envDefault := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		baseDir = filepath.Join(home, ".jvmdiag")
	}
	_ = os.MkdirAll(baseDir, 0o755)

	m := &Manager{
		options: opts, getenv: getenv,
		baseDir:   baseDir,
		wsConfigs: make(map[string]AIConfig),
		globalConfig: AIConfig{
			BaseURL:     DefaultBaseURL,
			Model:       DefaultModel,
			Temperature: DefaultTemperature,
		},
		matHome:     envDefault("APP_MAT_HOME", "/opt/mat"),
		matHeapSize: getenv("MAT_HEAP_SIZE"),
		maxMatMem:   envDefault("DYNAMIC_MAX_MAT_MEMORY", "8g"),
		multiUser:   getenv("MULTI_USER_MODE") == "true" || getenv("MULTI_USER_MODE") == "1",
		maxWorkers:  2,
	}
	if mw := getenv("MAX_WORKERS"); mw != "" {
		if v, err := strconv.Atoi(mw); err == nil && v > 0 {
			m.maxWorkers = v
		}
	}

	m.loadGlobal()
	return m
}

func (m *Manager) LegacySourcesEnabled() bool { return !m.options.SkipLegacy }

func (m *Manager) BaseDir() string {
	return m.baseDir
}

func (m *Manager) SetMultiUser(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.multiUser = enabled
}

func (m *Manager) IsMultiUser() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.multiUser
}

func (m *Manager) SetMaxWorkers(workers int) {
	if workers > 0 {
		m.mu.Lock()
		m.maxWorkers = workers
		m.mu.Unlock()
	}
}

func (m *Manager) MaxWorkers() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxWorkers
}

func (m *Manager) MatHome() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.matHome
}

func (m *Manager) MatHeapSize() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.matHeapSize
}

func (m *Manager) MaxMatMemory() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxMatMem
}

func (m *Manager) loadGlobal() {
	cfgPath := filepath.Join(m.baseDir, "config.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		var cfg AIConfig
		if json.Unmarshal(data, &cfg) == nil {
			m.globalConfig = mergeWithDefaults(cfg)
			return
		}
	}

	if m.options.SkipLegacy {
		return
	}
	// Fallback: check legacy ~/.jvm-diagnostics/config.properties from Spring Boot app
	home, err := os.UserHomeDir()
	if err == nil {
		legacyPath := filepath.Join(home, ".jvm-diagnostics", "config.properties")
		if f, err := os.Open(legacyPath); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				k := strings.TrimSpace(parts[0])
				v := strings.ReplaceAll(strings.TrimSpace(parts[1]), `\:`, ":")
				switch k {
				case "api-key":
					m.globalConfig.APIKey = v
				case "base-url":
					if v != "" {
						m.globalConfig.BaseURL = v
					}
				case "model":
					if v != "" {
						m.globalConfig.Model = v
					}
				case "temperature":
					if t, err := strconv.ParseFloat(v, 64); err == nil {
						m.globalConfig.Temperature = t
					}
				case "trust-insecure-certs":
					m.globalConfig.TrustInsecureCerts = (v == "true")
				}
			}
		}
	}
}

func mergeWithDefaults(cfg AIConfig) AIConfig {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Temperature <= 0 {
		cfg.Temperature = DefaultTemperature
	}
	return cfg
}

// GetEffectiveConfig resolves AI config in priority order:
// 1. Workspace override (if set for this workspaceID)
// 2. Environment variables (OPENROUTER_API_KEY, etc.)
// 3. Global saved config (~/.jvmdiag/config.json)
func (m *Manager) GetEffectiveConfig(workspaceID string) (AIConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	workspaceID = SanitizeWorkspaceID(workspaceID)
	effective := m.globalConfig

	// Apply ENV overrides to global base
	if envKey := m.getenv("OPENROUTER_API_KEY"); isValidKey(envKey) {
		effective.APIKey = envKey
	} else if envKey := m.getenv("OPENAI_API_KEY"); isValidKey(envKey) {
		effective.APIKey = envKey
	}
	if envBase := m.getenv("OPENROUTER_BASE_URL"); envBase != "" {
		effective.BaseURL = envBase
	}
	if envModel := m.getenv("AI_MODEL"); envModel != "" {
		effective.Model = envModel
	}
	if envTemp := m.getenv("AI_TEMPERATURE"); envTemp != "" {
		if t, err := strconv.ParseFloat(envTemp, 64); err == nil {
			effective.Temperature = t
		}
	}
	if envInsecure := m.getenv("AI_TRUST_INSECURE_CERTS"); envInsecure != "" {
		effective.TrustInsecureCerts = (envInsecure == "true" || envInsecure == "1")
	}

	hasWorkspaceOverride := false
	if workspaceID != "" && workspaceID != DefaultWorkspace {
		wsCfg, ok := m.wsConfigs[workspaceID]
		if !ok {
			wsPath := filepath.Join(m.WorkspaceDir(workspaceID), "config.json")
			if data, err := os.ReadFile(wsPath); err == nil {
				if json.Unmarshal(data, &wsCfg) == nil {
					ok = true
				}
			}
		}
		if ok {
			if isValidKey(wsCfg.APIKey) {
				effective.APIKey = wsCfg.APIKey
				hasWorkspaceOverride = true
			}
			if wsCfg.BaseURL != "" {
				if wsCfg.BaseURL != effective.BaseURL && !isValidKey(wsCfg.APIKey) {
					effective.APIKey = ""
				}
				effective.BaseURL = wsCfg.BaseURL
			}
			if wsCfg.Model != "" {
				effective.Model = wsCfg.Model
			}
			if wsCfg.Temperature > 0 {
				effective.Temperature = wsCfg.Temperature
			}
			if wsCfg.TrustInsecureCerts {
				if !effective.TrustInsecureCerts && !isValidKey(wsCfg.APIKey) {
					effective.APIKey = ""
				}
				effective.TrustInsecureCerts = true
			}
		}
	}

	return mergeWithDefaults(effective), hasWorkspaceOverride
}

func (m *Manager) IsConfigured(workspaceID string) bool {
	cfg, _ := m.GetEffectiveConfig(workspaceID)
	return isValidKey(cfg.APIKey)
}

func (m *Manager) SaveConfig(workspaceID string, cfg AIConfig, applyGlobal bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg = mergeWithDefaults(cfg)
	workspaceID = SanitizeWorkspaceID(workspaceID)

	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: AI base URL must be an absolute HTTP(S) URL without credentials, query or fragment", ErrInvalidConfig)
	}
	if !applyGlobal && workspaceID == DefaultWorkspace {
		return fmt.Errorf("%w: default workspace settings require an explicit global update", ErrInvalidConfig)
	}
	if applyGlobal {
		// Changing provider requires an explicit key rather than silently forwarding the saved key.
		if cfg.APIKey == "" && cfg.BaseURL != m.globalConfig.BaseURL {
			return fmt.Errorf("%w: provide an API key explicitly when changing the AI endpoint", ErrInvalidConfig)
		}
		// If APIKey is empty on update, preserve existing APIKey
		if cfg.APIKey == "" {
			cfg.APIKey = m.globalConfig.APIKey
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(m.baseDir, "config.json"), data, 0o600); err != nil {
			return err
		}
		m.globalConfig = cfg
		return nil
	}

	// Save workspace-specific override
	existing, ok := m.wsConfigs[workspaceID]
	if !ok {
		data, _ := os.ReadFile(filepath.Join(m.WorkspaceDir(workspaceID), "config.json"))
		_ = json.Unmarshal(data, &existing)
	}
	if cfg.APIKey == "" {
		if existing.APIKey != "" && cfg.BaseURL != existing.BaseURL {
			return fmt.Errorf("%w: provide an API key explicitly when changing the AI endpoint", ErrInvalidConfig)
		}
		cfg.APIKey = existing.APIKey
	}
	wsDir := m.WorkspaceDir(workspaceID)
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(wsDir, "config.json"), data, 0o600); err != nil {
		return err
	}
	m.wsConfigs[workspaceID] = cfg
	return nil
}

func (m *Manager) MaskedAPIKey(workspaceID string) string {
	cfg, _ := m.GetEffectiveConfig(workspaceID)
	k := cfg.APIKey
	if !isValidKey(k) {
		return "Not configured"
	}
	if len(k) <= 10 {
		return "****"
	}
	return k[:6] + "..." + k[len(k)-4:]
}

func (m *Manager) ConfigFilePath(workspaceID string) string {
	workspaceID = SanitizeWorkspaceID(workspaceID)
	if workspaceID != DefaultWorkspace {
		wsPath := filepath.Join(m.WorkspaceDir(workspaceID), "config.json")
		if _, err := os.Stat(wsPath); err == nil {
			return wsPath
		}
	}
	return filepath.Join(m.baseDir, "config.json")
}

func (m *Manager) WorkspaceDir(workspaceID string) string {
	workspaceID = SanitizeWorkspaceID(workspaceID)
	return filepath.Join(m.baseDir, "workspaces", workspaceID)
}

// Prompt management (supports workspace-level custom prompts and global custom prompts)
func (m *Manager) GetCustomPrompt(workspaceID, promptType string) string {
	workspaceID = SanitizeWorkspaceID(workspaceID)
	if workspaceID != DefaultWorkspace {
		p := filepath.Join(m.WorkspaceDir(workspaceID), "prompts", promptType+".txt")
		if data, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(data)) != "" {
			return string(data)
		}
	}
	p := filepath.Join(m.baseDir, "prompts", promptType+".txt")
	if data, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(data)) != "" {
		return string(data)
	}
	return ""
}

func (m *Manager) SaveCustomPrompt(workspaceID, promptType, content string) error {
	workspaceID = SanitizeWorkspaceID(workspaceID)
	dir := filepath.Join(m.baseDir, "prompts")
	if workspaceID != DefaultWorkspace {
		dir = filepath.Join(m.WorkspaceDir(workspaceID), "prompts")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, promptType+".txt"), []byte(content), 0o644)
}

func (m *Manager) ResetCustomPrompt(workspaceID, promptType string) error {
	workspaceID = SanitizeWorkspaceID(workspaceID)
	p := filepath.Join(m.baseDir, "prompts", promptType+".txt")
	if workspaceID != DefaultWorkspace {
		p = filepath.Join(m.WorkspaceDir(workspaceID), "prompts", promptType+".txt")
	}
	err := os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

var wsRegex = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func SanitizeWorkspaceID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return DefaultWorkspace
	}
	cleaned := wsRegex.ReplaceAllString(id, "-")
	if len(cleaned) > 64 {
		cleaned = cleaned[:64]
	}
	if cleaned == "" {
		return DefaultWorkspace
	}
	return cleaned
}

func isValidKey(k string) bool {
	k = strings.TrimSpace(k)
	return k != "" && k != "sk-placeholder" && k != "sk-or-your-key-here"
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadDotEnvFiles(paths ...string) {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.TrimSpace(parts[0])
			v := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			if k != "" && v != "" && os.Getenv(k) == "" {
				_ = os.Setenv(k, v)
			}
		}
		f.Close()
	}
}
