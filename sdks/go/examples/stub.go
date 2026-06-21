package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

// startStubServer returns an in-process httptest.Server that mimics the
// PromptSentinel HTTP API closely enough to drive every step of the example
// deterministically. It is used only when PROMPTSENTINEL_DEMO is set, so the
// walkthrough runs with no real service and no real LLM.
//
// The stub's "detection" is intentionally simple keyword matching — it exists
// to produce realistic-looking responses (allowed/reasons/refusal/canary/
// would_block/mode), NOT to be an actual scanner.
func startStubServer() *httptest.Server {
	const canary = "PSCANARY-7f3a9c1e"
	const refusal = "I can't help with that request."

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(v)
	}
	readBody := func(r *http.Request) map[string]any {
		m := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	str := func(m map[string]any, k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/system-prompt/build", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		writeJSON(w, map[string]any{
			"hardened_system_prompt": "[[HARDENED]] " + str(body, "base_prompt") +
				" [[canary:" + canary + "]]",
			"canary": canary,
		})
	})

	mux.HandleFunc("/v1/screen/input", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		text := strings.ToLower(str(body, "user_input") + " " + str(body, "untrusted_context"))

		// Hard injection -> blocked under enforce.
		if strings.Contains(text, "ignore all previous instructions") ||
			strings.Contains(text, "reveal your system prompt") {
			writeJSON(w, map[string]any{
				"allowed":     false,
				"risk":        0.97,
				"reasons":     []string{"injection_heuristic", "ml_classifier"},
				"sanitized":   "",
				"refusal":     refusal,
				"would_block": true,
				"mode":        "enforce",
			})
			return
		}

		// Borderline phrasing -> shadow mode: allowed but would_block=true.
		if strings.Contains(text, "disregard the above") {
			writeJSON(w, map[string]any{
				"allowed":     true,
				"risk":        0.78,
				"reasons":     []string{"injection_heuristic"},
				"sanitized":   str(body, "user_input"),
				"refusal":     nil,
				"would_block": true,
				"mode":        "shadow",
			})
			return
		}

		// Benign.
		writeJSON(w, map[string]any{
			"allowed":     true,
			"risk":        0.02,
			"reasons":     []string{},
			"sanitized":   str(body, "user_input"),
			"refusal":     nil,
			"would_block": false,
			"mode":        "enforce",
		})
	})

	mux.HandleFunc("/v1/screen/output", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		out := str(body, "model_output")
		can := str(body, "canary")

		// Canary leak detected -> block, replace text with a refusal.
		if can != "" && strings.Contains(out, can) {
			writeJSON(w, map[string]any{
				"allowed":     false,
				"risk":        1.0,
				"reasons":     []string{"canary"},
				"text":        "I'm sorry, I can't share that information.",
				"would_block": true,
				"mode":        "enforce",
			})
			return
		}

		writeJSON(w, map[string]any{
			"allowed":     true,
			"risk":        0.0,
			"reasons":     []string{},
			"text":        out,
			"would_block": false,
			"mode":        "enforce",
		})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"status": "ok", "team": "core", "agent": "default",
			"llm_guard": true, "llm_judge": false, "protected_terms": 7,
			"mode": "enforce", "ml_classifier": true,
		})
	})

	return httptest.NewServer(mux)
}
