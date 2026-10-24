package ai

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bishoku/jvmdiag/internal/config"
)

func TestChatTurnSlidingWindowAndClear(t *testing.T) {
	cfg := config.NewManagerWithOptions(t.TempDir(), config.Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true})
	svc := NewService(cfg, nil)
	ws := "default"
	sessionID := "test-session"

	st := svc.GetChatStatus(ws, sessionID)
	if got := st["turnCount"].(int); got != 0 {
		t.Fatalf("expected 0 initial turns, got %d", got)
	}

	// Simulate 14 turns (> MaxChatTurns = 10)
	for i := 1; i <= 14; i++ {
		svc.mu.Lock()
		turns := append(svc.chatTurns[svc.mcpServerSession(ws, sessionID)], ChatTurn{
			UserMessage:      fmt.Sprintf("user question %d", i),
			AssistantMessage: fmt.Sprintf("assistant answer %d", i),
			ToolsUsed:        []string{"get_class_histogram(filter=com.example)"},
		})
		if len(turns) > MaxChatTurns {
			turns = turns[len(turns)-MaxChatTurns:]
		}
		svc.chatTurns[svc.mcpServerSession(ws, sessionID)] = turns
		svc.mu.Unlock()
	}

	st = svc.GetChatStatus(ws, sessionID)
	if got := st["turnCount"].(int); got != MaxChatTurns {
		t.Fatalf("expected %d turns after sliding window cap, got %d", MaxChatTurns, got)
	}

	// Verify oldest turns (1..4) were rotated out and turn 5 is now first
	svc.mu.Lock()
	firstUser := svc.chatTurns[svc.mcpServerSession(ws, sessionID)][0].UserMessage
	lastUser := svc.chatTurns[svc.mcpServerSession(ws, sessionID)][MaxChatTurns-1].UserMessage
	svc.mu.Unlock()

	if firstUser != "user question 5" {
		t.Fatalf("expected oldest retained turn to be 'user question 5', got %q", firstUser)
	}
	if lastUser != "user question 14" {
		t.Fatalf("expected latest retained turn to be 'user question 14', got %q", lastUser)
	}

	// Clear chat history
	svc.ClearChatHistory(ws, sessionID)
	st = svc.GetChatStatus(ws, sessionID)
	if got := st["turnCount"].(int); got != 0 {
		t.Fatalf("expected 0 turns after ClearChatHistory, got %d", got)
	}
}

func TestChatMemoryIsWorkspaceScoped(t *testing.T) {
	svc := NewService(config.NewManagerWithOptions(t.TempDir(), config.Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true}), nil)
	svc.chatTurns[svc.mcpServerSession("alpha", "same-id")] = []ChatTurn{{UserMessage: "private-alpha"}}
	if svc.GetChatStatus("beta", "same-id")["turnCount"].(int) != 0 {
		t.Fatal("chat history crossed workspace")
	}
	svc.ClearChatHistory("beta", "same-id")
	if svc.GetChatStatus("alpha", "same-id")["turnCount"].(int) != 1 {
		t.Fatal("foreign clear removed chat history")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAIProviderRedirectCannotForwardAPIKey(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "provider.example" {
			t.Error("API key forwarded to another endpoint")
		}
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://attacker.example/steal"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	_, err := (&Service{transport: transport}).doChatRequest(context.Background(), config.AIConfig{APIKey: "provider-secret", BaseURL: "https://provider.example/v1"}, map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") || calls != 1 {
		t.Fatalf("redirect not blocked: calls=%d error=%v", calls, err)
	}
}
