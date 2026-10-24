package config

import (
	"os"
	"path/filepath"
	"testing"
)

func isolatedManager(t *testing.T, base string) *Manager {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	for _, key := range []string{"OPENAI_API_KEY", "OPENROUTER_API_KEY"} {
		t.Setenv(key, "sk-placeholder")
	}
	t.Setenv("OPENROUTER_BASE_URL", "")
	return NewManagerWithOptions(base, Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true})
}

func TestWorkspaceEndpointCannotInheritGlobalKey(t *testing.T) {
	m := isolatedManager(t, t.TempDir())
	if err := m.SaveConfig("default", AIConfig{APIKey: "global-secret", BaseURL: "https://provider.example/v1"}, true); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveConfig("alpha", AIConfig{BaseURL: "https://other.example/v1"}, false); err != nil {
		t.Fatal(err)
	}
	cfg, _ := m.GetEffectiveConfig("alpha")
	if cfg.APIKey != "" {
		t.Fatal("global key forwarded to different endpoint")
	}
	if err := m.SaveConfig("default", AIConfig{BaseURL: "https://other.example/v1"}, true); err == nil {
		t.Fatal("global endpoint changed without explicit key")
	}
	cfg, _ = m.GetEffectiveConfig("default")
	if cfg.APIKey != "global-secret" || cfg.BaseURL != "https://provider.example/v1" {
		t.Fatal("rejected save changed in-memory settings")
	}
}

func TestWorkspaceKeyPreservedAfterRestart(t *testing.T) {
	base := t.TempDir()
	m := isolatedManager(t, base)
	initial := AIConfig{APIKey: "alpha-secret", BaseURL: "https://provider.example/v1", Model: "old"}
	if err := m.SaveConfig("alpha", initial, false); err != nil {
		t.Fatal(err)
	}
	m = NewManagerWithOptions(base, Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true})
	if err := m.SaveConfig("alpha", AIConfig{BaseURL: initial.BaseURL, Model: "new"}, false); err != nil {
		t.Fatal(err)
	}
	cfg, _ := m.GetEffectiveConfig("alpha")
	if cfg.APIKey != "alpha-secret" || cfg.Model != "new" {
		t.Fatal("workspace key lost after restart")
	}
	if err := m.SaveConfig("alpha", AIConfig{BaseURL: "https://attacker.example/v1"}, false); err == nil {
		t.Fatal("workspace key silently moved to new provider")
	}
}

func TestInvalidEndpointAndFailedSaveLeaveConfigUnchanged(t *testing.T) {
	m := isolatedManager(t, t.TempDir())
	for _, endpoint := range []string{"file:///etc/passwd", "https://user:pass@example.com", "https://example.com?key=x", "https://example.com#fragment", "//example.com"} {
		if err := m.SaveConfig("default", AIConfig{BaseURL: endpoint, APIKey: "secret"}, true); err == nil {
			t.Fatalf("invalid endpoint accepted: %s", endpoint)
		}
	}
	// A failed disk write must not publish the new configuration in memory.
	if err := os.Mkdir(filepath.Join(m.BaseDir(), "config.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveConfig("default", AIConfig{APIKey: "secret", Model: "new"}, true); err == nil {
		t.Fatal("expected failed write")
	}
	cfg, _ := m.GetEffectiveConfig("default")
	if cfg.Model == "new" || cfg.APIKey == "secret" {
		t.Fatal("failed persistence mutated configuration")
	}
}

func TestWorkspaceCannotDisableTLSWithInheritedKey(t *testing.T) {
	m := isolatedManager(t, t.TempDir())
	if err := m.SaveConfig("default", AIConfig{APIKey: "global-secret", BaseURL: "https://provider.example/v1"}, true); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveConfig("alpha", AIConfig{BaseURL: "https://provider.example/v1", TrustInsecureCerts: true}, false); err != nil {
		t.Fatal(err)
	}
	cfg, _ := m.GetEffectiveConfig("alpha")
	if cfg.APIKey != "" {
		t.Fatal("inherited key exposed through insecure workspace TLS")
	}
}

func TestIsolatedManagerIgnoresAmbientSecretsAndLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENROUTER_API_KEY", "ambient-secret")
	t.Setenv("OPENROUTER_BASE_URL", "https://ambient.example")
	t.Setenv("AI_MODEL", "ambient-model")
	t.Setenv("APP_MAT_HOME", "/ambient/mat")
	t.Setenv("MAX_WORKERS", "99")
	legacy := filepath.Join(home, ".jvm-diagnostics")
	if err := os.Mkdir(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "config.properties"), []byte("api-key=legacy-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManagerWithOptions(t.TempDir(), Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true})
	cfg, _ := m.GetEffectiveConfig("default")
	if cfg.APIKey != "" || cfg.BaseURL != DefaultBaseURL || cfg.Model != DefaultModel || m.MaxWorkers() != 2 || m.MatHome() != "/opt/mat" {
		t.Fatalf("isolated manager imported ambient values: configured=%v", m.IsConfigured("default"))
	}
}
