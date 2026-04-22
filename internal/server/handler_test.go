package server

import (
	"testing"
)

func TestIsRegexPattern(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"ls", false},
		{"^ls", true},
		{"ls$", true},
		{"l.s", true},
		{"ls.*", true},
		{"ls+", true},
		{"ls?", true},
		{"(ls)", true},
		{"[ls]", true},
		{"{ls}", true},
		{"ls|rm", true},
		{"ls\\", true},
		{"", false},
		{"ls -l", false},
		{"^ls.* -l$", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := isRegexPattern(tt.pattern)
			if got != tt.want {
				t.Errorf("isRegexPattern(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchesCommand(t *testing.T) {
	tests := []struct {
		pattern string
		cmd     string
		want    bool
	}{
		// Exact matches (no regex metacharacters)
		{"ls", "ls", true},
		{"ls", "ls -l", false}, // baseCmd is "ls", but pattern expects exact match, so false
		{"ls", "mkdir", false},
		// Regex matches
		{"^ls.*", "ls", true},
		{"^ls.*", "ls -l", true},
		{"^ls.*", "ls -la", true},
		{"^ls.*", "mkdir", false},
		{"^rm.*", "rm", true},
		{"^rm.*", "rm -rf", true},
		{"^rm.*", "ls", false},
		// Invalid regex falls back to exact match
		{"[", "[", true}, // invalid regex, treat as literal
		{"[", "ls", false},
		// Case sensitive
		{"ls", "LS", false},
		{"^[Ll][Ss].*", "ls", true},
		{"^[Ll][Ss].*", "Ls -l", true},
		// Complex patterns with metacharacters
		{"^rm\\s+-f.*", "rm -f file", true},
		{"^rm\\s+-f.*", "rm -rf file", false},
		{"^echo\\s+\".*\"$", "echo \"hello\"", true},
		{"^echo\\s+\".*\"$", "echo hello", false},
		// Edge: pattern with backslash but escaped
		{"^ls\\b", "ls", true},
		{"^ls\\b", "ls -l", true}, // word boundary matches
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.cmd, func(t *testing.T) {
			got := matchesCommand(tt.pattern, tt.cmd)
			if got != tt.want {
				t.Errorf("matchesCommand(%q, %q) = %v, want %v", tt.pattern, tt.cmd, got, tt.want)
			}
		})
	}
}
