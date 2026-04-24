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

func TestResolveStoragePath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory structure
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		root    string
		path    string
		want    string
		wantErr bool
	}{
		{"empty filename", tmpDir, "", "", true},
		{"simple name", tmpDir, "test.txt", filepath.Join(tmpDir, "test.txt"), false},
		{"subdir file", tmpDir, "subdir/file.txt", filepath.Join(tmpDir, "subdir/file.txt"), false},
		{"absolute path", tmpDir, "/etc/passwd", "", true},
		{"parent traversal", tmpDir, "..", "", true},
		{"deep traversal", tmpDir, "../../etc/passwd", "", true},
		{"current dir", tmpDir, ".", "", true},
		{"nested traversal", tmpDir, "subdir/../../etc", "", true},
		{"clean dot", tmpDir, "./test.txt", filepath.Join(tmpDir, "test.txt"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveStoragePath(tt.root, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveStoragePath(%q, %q) error = %v, wantErr %v", tt.root, tt.path, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("resolveStoragePath(%q, %q) = %q, want %q", tt.root, tt.path, got, tt.want)
			}
		})
	}
}

func TestResolveStoragePathRejectsSymlinkComponents(t *testing.T) {
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(tmpDir, "link")
	if err := os.Symlink(targetDir, linkPath); err != nil {
		t.Fatal(err)
	}

	_, err := resolveStoragePath(tmpDir, "link/file.txt")
	if err == nil {
		t.Fatal("resolveStoragePath() expected error for symlink component")
	}
}

func TestComputeRootDir(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("home policy without subdir", func(t *testing.T) {
		sc := &StorageConfig{
			Mode:           "virtual-root",
			UserRootPolicy: "home",
			UserSubdir:     "",
		}
		got, err := computeRootDir(sc, tmpDir, "testuser")
		if err != nil {
			t.Fatalf("computeRootDir() error = %v", err)
		}
		absHome, _ := filepath.Abs(tmpDir)
		if got != absHome {
			t.Errorf("computeRootDir() = %q, want %q", got, absHome)
		}
	})

	t.Run("home policy with subdir", func(t *testing.T) {
		sc := &StorageConfig{
			Mode:           "virtual-root",
			UserRootPolicy: "home",
			UserSubdir:     "quics",
		}
		got, err := computeRootDir(sc, tmpDir, "testuser")
		if err != nil {
			t.Fatalf("computeRootDir() error = %v", err)
		}
		want := filepath.Join(tmpDir, "quics")
		absWant, _ := filepath.Abs(want)
		if got != absWant {
			t.Errorf("computeRootDir() = %q, want %q", got, absWant)
		}
	})

	t.Run("subdir policy without subdir", func(t *testing.T) {
		sc := &StorageConfig{
			Mode:           "virtual-root",
			RootDir:        tmpDir,
			UserRootPolicy: "subdir",
			UserSubdir:     "",
		}
		got, err := computeRootDir(sc, "/nonexistent/home", "testuser")
		if err != nil {
			t.Fatalf("computeRootDir() error = %v", err)
		}
		want := filepath.Join(tmpDir, "testuser")
		absWant, _ := filepath.Abs(want)
		if got != absWant {
			t.Errorf("computeRootDir() = %q, want %q", got, absWant)
		}
	})

	t.Run("subdir policy with subdir", func(t *testing.T) {
		sc := &StorageConfig{
			Mode:           "virtual-root",
			RootDir:        tmpDir,
			UserRootPolicy: "subdir",
			UserSubdir:     "data",
		}
		got, err := computeRootDir(sc, "/nonexistent/home", "testuser")
		if err != nil {
			t.Fatalf("computeRootDir() error = %v", err)
		}
		want := filepath.Join(tmpDir, "testuser", "data")
		absWant, _ := filepath.Abs(want)
		if got != absWant {
			t.Errorf("computeRootDir() = %q, want %q", got, absWant)
		}
	})

	t.Run("unknown policy", func(t *testing.T) {
		sc := &StorageConfig{
			Mode:           "virtual-root",
			UserRootPolicy: "invalid",
		}
		_, err := computeRootDir(sc, tmpDir, "testuser")
		if err == nil {
			t.Error("computeRootDir() expected error for unknown policy")
		}
	})
}

func TestResolveLocalUser_NotFound(t *testing.T) {
	_, _, _, _, err := resolveLocalUser("thisuserdoesnotexist_12345")
	if err == nil {
		t.Error("resolveLocalUser() expected error for non-existent user")
	}
}

func TestBuildSessionEnvUsesDefaultPath(t *testing.T) {
	sess := &Session{
		LocalUser:   "alice",
		HomeDir:     "/home/alice",
		JailHomeDir: "/",
		Shell:       "/bin/sh",
	}

	env := buildSessionEnv(sess)
	foundPath := false
	for _, entry := range env {
		if entry == "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
			foundPath = true
			break
		}
	}
	if !foundPath {
		t.Fatal("buildSessionEnv() did not set default PATH")
	}
	foundHome := false
	for _, entry := range env {
		if entry == "HOME=/" {
			foundHome = true
			break
		}
	}
	if !foundHome {
		t.Fatal("buildSessionEnv() did not set jail-aware HOME")
	}
}

func TestSessionCopyPreservesJailHome(t *testing.T) {
	sess := &Session{
		LocalUser:   "alice",
		HomeDir:     "/home/alice",
		JailHomeDir: "/",
		EnvVars:     []string{"PATH=/bin"},
	}

	copied := sess.Copy()
	if copied.JailHomeDir != "/" {
		t.Fatalf("Session.Copy() JailHomeDir = %q, want /", copied.JailHomeDir)
	}
	if len(copied.EnvVars) != 1 || copied.EnvVars[0] != "PATH=/bin" {
		t.Fatalf("Session.Copy() EnvVars = %v, want [PATH=/bin]", copied.EnvVars)
	}
}

func TestResolveExecutableInRoot(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	exePath := filepath.Join(binDir, "tool")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("find in PATH", func(t *testing.T) {
		env := []string{"PATH=/bin"}
		got, err := resolveExecutableInRoot("tool", env, tmpDir)
		if err != nil {
			t.Fatalf("resolveExecutableInRoot() error = %v", err)
		}
		if got != "/bin/tool" {
			t.Fatalf("resolveExecutableInRoot() = %q, want %q", got, "/bin/tool")
		}
	})

	t.Run("reject outside root", func(t *testing.T) {
		env := []string{"PATH=/usr/bin"}
		if _, err := resolveExecutableInRoot("tool", env, tmpDir); err == nil {
			t.Fatal("resolveExecutableInRoot() expected error when executable is not inside root")
		}
	})
}
