package server

import (
	"os"
	"path/filepath"
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

func TestGetUserHomeDir(t *testing.T) {
	tempDir := t.TempDir()
	
	server := &Server{config: &Config{StorageRoot: tempDir}}
	
	// Test normal user
	homeDir, err := server.getUserHomeDir("testuser")
	if err != nil {
		t.Fatalf("getUserHomeDir failed: %v", err)
	}
	expected := filepath.Join(tempDir, "testuser")
	if homeDir != expected {
		t.Errorf("getUserHomeDir(\"testuser\") = %q, want %q", homeDir, expected)
	}
	// Verify directory created with 0700 permissions
	info, err := os.Stat(homeDir)
	if err != nil {
		t.Fatalf("stat home directory: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("home directory permissions = %o, want %o", info.Mode().Perm(), 0700)
	}
	
	// Test root user
	rootHome, err := server.getUserHomeDir("root")
	if err != nil {
		t.Fatalf("getUserHomeDir(root) failed: %v", err)
	}
	if rootHome != tempDir {
		t.Errorf("getUserHomeDir(\"root\") = %q, want %q", rootHome, tempDir)
	}
	
	// Test another user
	homeDir2, err := server.getUserHomeDir("user2")
	if err != nil {
		t.Fatalf("getUserHomeDir(user2) failed: %v", err)
	}
	expected2 := filepath.Join(tempDir, "user2")
	if homeDir2 != expected2 {
		t.Errorf("getUserHomeDir(\"user2\") = %q, want %q", homeDir2, expected2)
	}
}

func TestResolvePathRelativeToHome(t *testing.T) {
	tempDir := t.TempDir()
	server := &Server{config: &Config{StorageRoot: tempDir}}
	
	homeDir := filepath.Join(tempDir, "testuser")
	if err := os.MkdirAll(homeDir, 0700); err != nil {
		t.Fatal(err)
	}
	
	tests := []struct {
		name        string
		filename    string
		homeDir     string
		want        string
		shouldError bool
	}{
		{
			name:     "simple file",
			filename: "file.txt",
			homeDir:  homeDir,
			want:     filepath.Join(homeDir, "file.txt"),
		},
		{
			name:     "subdirectory",
			filename: "subdir/file.txt",
			homeDir:  homeDir,
			want:     filepath.Join(homeDir, "subdir/file.txt"),
		},
		{
			name:        "path traversal blocked",
			filename:    "../outside.txt",
			homeDir:     homeDir,
			shouldError: true,
		},
		{
			name:        "multiple traversal",
			filename:    "../../../etc/passwd",
			homeDir:     homeDir,
			shouldError: true,
		},
		{
			name:     "absolute path stripped",
			filename: "/absolute/path",
			homeDir:  homeDir,
			want:     filepath.Join(homeDir, "absolute/path"),
		},
		{
			name:     "dot path",
			filename: "././file.txt",
			homeDir:  homeDir,
			want:     filepath.Join(homeDir, "file.txt"),
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := server.resolvePathRelativeToHome(tt.filename, tt.homeDir)
			if tt.shouldError {
				if err == nil {
					t.Errorf("resolvePathRelativeToHome(%q, %q) = %q, want error", tt.filename, tt.homeDir, got)
				}
				return
			}
			if err != nil {
				t.Errorf("resolvePathRelativeToHome(%q, %q) error: %v", tt.filename, tt.homeDir, err)
				return
			}
			if got != tt.want {
				t.Errorf("resolvePathRelativeToHome(%q, %q) = %q, want %q", tt.filename, tt.homeDir, got, tt.want)
			}
		})
	}
}
