package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/francesco/quics/internal/protocol"
	"github.com/quic-go/quic-go"
)

type Server struct {
	config *Config
}

type Config struct {
	StorageRoot string
	ShellConfig *ShellConfig
}

type ShellConfig struct {
	Enabled          bool
	AllowedCommands  []string
	MaxExecutionTime int
	AllowedEnvVars   []string
}

type session struct {
	userid    string
	homeDir   string
	envVars   []string
	workingDir string
}

// isRegexPattern returns true if the pattern contains regex metacharacters.
func isRegexPattern(pattern string) bool {
	// List of regex metacharacters that indicate a regex pattern
	metachars := []string{"^", "$", ".", "*", "+", "?", "(", ")", "[", "]", "{", "}", "|", "\\"}
	for _, ch := range metachars {
		if strings.Contains(pattern, ch) {
			return true
		}
	}
	return false
}

// matchesCommand checks if a command matches an allowed pattern.
// Patterns containing regex metacharacters are treated as regex, otherwise as exact match.
func matchesCommand(pattern, cmd string) bool {
	if isRegexPattern(pattern) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// If pattern is invalid regex, fall back to exact match
			return pattern == cmd
		}
		return re.MatchString(cmd)
	}
	// No regex metacharacters, treat as exact match
	return pattern == cmd
}

// resolvePath resolves a filename relative to StorageRoot and ensures it stays within StorageRoot.
func (s *Server) resolvePath(filename string) (string, error) {
	// Clean the path
	cleanPath := filepath.Clean(filename)
	// If path is absolute, treat as relative to root (strip leading slash)
	if filepath.IsAbs(cleanPath) {
		cleanPath = cleanPath[1:]
	}
	// Join with StorageRoot
	fullPath := filepath.Join(s.config.StorageRoot, cleanPath)
	// Ensure the result is within StorageRoot
	rel, err := filepath.Rel(s.config.StorageRoot, fullPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	if strings.HasPrefix(rel, "..") || strings.Contains(rel, "../") {
		return "", fmt.Errorf("path attempts to escape storage root")
	}
	return fullPath, nil
}

// getAbsWorkingDir returns the absolute working directory for a session.
// It joins StorageRoot with session's workingDir and ensures the path is within StorageRoot.
func (s *Server) getAbsWorkingDir(sess *session) (string, error) {
	if sess.workingDir == "" || sess.workingDir == "." {
		return sess.homeDir, nil
	}
	return s.resolvePathRelativeToHome(sess.workingDir, sess.homeDir)
}

// getUserHomeDir returns the home directory path for a given userid.
// For root user, returns StorageRoot directly.
// For other users, returns StorageRoot/userid and creates the directory if it doesn't exist.
func (s *Server) getUserHomeDir(userid string) (string, error) {
	var homeDir string
	if userid == "root" {
		homeDir = s.config.StorageRoot
	} else {
		homeDir = filepath.Join(s.config.StorageRoot, userid)
	}
	
	fmt.Printf("Creating home directory for user %s at %s\n", userid, homeDir)
	// Create directory if it doesn't exist
	if err := os.MkdirAll(homeDir, 0700); err != nil {
		fmt.Printf("Failed to create home directory for %s: %v\n", userid, err)
		return "", fmt.Errorf("failed to create home directory for %s: %w", userid, err)
	}
	
	fmt.Printf("Home directory created/verified for %s: %s\n", userid, homeDir)
	return homeDir, nil
}

// resolvePathRelativeToHome resolves a filename relative to user's home directory.
// Ensures the result stays within the home directory.
func (s *Server) resolvePathRelativeToHome(filename, homeDir string) (string, error) {
	// Clean the path
	cleanPath := filepath.Clean(filename)
	// If path is absolute, treat as relative to root (strip leading slash)
	if filepath.IsAbs(cleanPath) {
		cleanPath = cleanPath[1:]
	}
	// Join with home directory
	fullPath := filepath.Join(homeDir, cleanPath)
	// Ensure the result is within home directory
	rel, err := filepath.Rel(homeDir, fullPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	if strings.HasPrefix(rel, "..") || strings.Contains(rel, "../") {
		return "", fmt.Errorf("path attempts to escape home directory")
	}
	return fullPath, nil
}

// hasRequiredCapabilities returns true if the process has permission to set UID and/or GID.
// Returns true if running as root (euid == 0) or if the required capabilities are present.
// needUID and needGID indicate which capabilities are required.
func hasRequiredCapabilities(needUID, needGID bool) bool {
	if os.Geteuid() == 0 {
		return true
	}
	// Check capabilities on Linux
	if runtime.GOOS != "linux" {
		return false
	}
	// Read effective capabilities from /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Parse hex capability set
				var capEff uint64
				fmt.Sscanf(parts[1], "%x", &capEff)
				// Check CAP_SETUID (bit 7) and CAP_SETGID (bit 6)
				hasSetuid := (capEff&(1<<7)) != 0
				hasSetgid := (capEff&(1<<6)) != 0
				if needUID && !hasSetuid {
					return false
				}
				if needGID && !hasSetgid {
					return false
				}
				return true
			}
			break
		}
	}
	return false
}

func NewServer(config *Config) *Server {
	return &Server{config: config}
}

func (s *Server) HandleStream(stream *quic.Stream, userid string) error {
	defer stream.Close()

	// Calculate user's home directory
	homeDir, err := s.getUserHomeDir(userid)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to setup user home: %v", err))))
		return fmt.Errorf("failed to setup user home for %s: %w", userid, err)
	}

	sess := &session{
		userid:    userid,
		homeDir:   homeDir,
		workingDir: ".",
	}
	fmt.Printf("User session created: userid=%s, homeDir=%s\n", userid, homeDir)
	reader := bufio.NewReader(stream)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading command: %w", err)
		}

		cmd, err := protocol.ParseCommand(line)
		if err != nil {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
			return err
		}
		fmt.Printf("Handling command: %s, args: %v, size: %d, mode: %s\n", cmd.Type, cmd.Args, cmd.Size, cmd.Mode)

		switch cmd.Type {
		case protocol.CommandUpload, protocol.CommandPut:
			if err := s.handleUpload(stream, cmd, sess, reader); err != nil {
				return err
			}
		case protocol.CommandDownload, protocol.CommandGet:
			if err := s.handleDownload(stream, cmd, sess); err != nil {
				return err
			}
		case protocol.CommandCmd:
			if err := s.handleCommand(stream, cmd, sess); err != nil {
				return err
			}
		case protocol.CommandExec:
			if err := s.handleExec(stream, cmd, sess); err != nil {
				return err
			}
		case protocol.CommandEnv:
			if err := s.handleEnv(stream, cmd, sess); err != nil {
				return err
			}
		case protocol.CommandCD:
			if err := s.handleCD(stream, cmd, sess); err != nil {
				return err
			}
		default:
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "unknown command")))
			return fmt.Errorf("unknown command type: %s", cmd.Type)
		}
	}
}

func (s *Server) handleUpload(stream *quic.Stream, cmd *protocol.Command, sess *session, reader *bufio.Reader) error {
	filename := cmd.Args[0]
	filePath, err := s.resolvePathRelativeToHome(filename, sess.homeDir)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("invalid file path: %v", err))))
		return err
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create directory: %v", err))))
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create file: %v", err))))
		return err
	}
	defer file.Close()

	var writer io.Writer = file
	var dataReader io.Reader = reader
	if cmd.Mode == protocol.ModeASCII {
		dataReader = protocol.ASCIIReader(reader)
	}

	written, err := io.CopyN(writer, dataReader, cmd.Size)
	if err != nil && err != io.EOF {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to write file: %v", err))))
		return err
	}

	if written != cmd.Size {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("incomplete transfer: expected %d bytes, got %d", cmd.Size, written))))
		return fmt.Errorf("incomplete transfer")
	}

	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("%d bytes written", written))))
	return nil
}

func (s *Server) handleDownload(stream *quic.Stream, cmd *protocol.Command, sess *session) error {
	filename := cmd.Args[0]
	filePath, err := s.resolvePathRelativeToHome(filename, sess.homeDir)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("invalid file path: %v", err))))
		return err
	}
	fmt.Printf("Download request for user %s: %s (path: %s)\n", sess.userid, filename, filePath)

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "file not found")))
		} else {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to open file: %v", err))))
		}
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to stat file: %v", err))))
		return err
	}

	size := stat.Size()

	response := protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("%d", size))
	fmt.Printf("Sending response: %s", response)
	stream.Write([]byte(response))

	var reader io.Reader = file
	var writer io.Writer = stream
	if cmd.Mode == protocol.ModeASCII {
		writer = protocol.ASCIIWriter(stream)
	}

	n, err := io.Copy(writer, reader)
	if err != nil {
		return fmt.Errorf("failed to send file: %w", err)
	}
	fmt.Printf("File sent successfully, size: %d, sent: %d\n", size, n)
	return nil
}

func (s *Server) handleCommand(stream *quic.Stream, cmd *protocol.Command, sess *session) error {
	if !s.config.ShellConfig.Enabled {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "shell execution is disabled")))
		return nil
	}

	// Check command against whitelist
	allowed := s.config.ShellConfig.AllowedCommands
	if len(allowed) > 0 {
		baseCmd := cmd.Args[0]
		found := false
		for _, pattern := range allowed {
			if matchesCommand(pattern, baseCmd) {
				found = true
				break
			}
		}
		if !found {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("command not allowed: %s", baseCmd))))
			return nil
		}
	}

	// Build environment variables
	env := os.Environ()
	for _, envVar := range sess.envVars {
		env = append(env, envVar)
	}

	// Execute command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.ShellConfig.MaxExecutionTime)*time.Second)
	defer cancel()

	cmdStr := strings.Join(cmd.Args, " ")
	fmt.Printf("Executing command: %s\n", cmdStr)
	execCmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	execCmd.Env = env
	workingDir, err := s.getAbsWorkingDir(sess)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("invalid working directory: %v", err))))
		return nil
	}
	execCmd.Dir = workingDir

	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stdout pipe: %v", err))))
		return nil // Don't return error to keep stream open
	}
	stderr, err := execCmd.StderrPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stderr pipe: %v", err))))
		return nil // Don't return error to keep stream open
	}

	if err := execCmd.Start(); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to start command: %v", err))))
		return nil // Don't return error to keep stream open
	}

	// Read stdout and stderr concurrently
	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(&stdoutBuf, stdout)
	}()
	go func() {
		defer wg.Done()
		io.Copy(&stderrBuf, stderr)
	}()
	wg.Wait()

	err = execCmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Send response according to protocol: OK\n<exit_code>\n<stdout_size>\n<stdout>\n<stderr_size>\n<stderr>
	response := fmt.Sprintf("%s\n%d\n%d\n%s\n%d\n%s", protocol.ResponseOK, exitCode, stdoutBuf.Len(), stdoutBuf.String(), stderrBuf.Len(), stderrBuf.String())
	fmt.Printf("Sending command response, exit code: %d, stdout: %d bytes, stderr: %d bytes\n", exitCode, stdoutBuf.Len(), stderrBuf.Len())
	_, err = stream.Write([]byte(response))
	if err != nil {
		fmt.Printf("Failed to send response: %v\n", err)
		return nil // Don't return error to keep stream open
	}

	// Clear environment variables after command execution
	sess.envVars = nil
	return nil
}

func (s *Server) handleExec(stream *quic.Stream, cmd *protocol.Command, sess *session) error {
	if !s.config.ShellConfig.Enabled {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "shell execution is disabled")))
		return nil
	}

	// Parse arguments: user, group, command
	if len(cmd.Args) < 3 {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "EXEC requires user, group and command")))
		return nil
	}
	userStr := cmd.Args[0]
	groupStr := cmd.Args[1]
	commandStr := cmd.Args[2]

	// Check if we're on Linux
	if runtime.GOOS != "linux" {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "EXEC is only supported on Linux")))
		return nil
	}

	// Get current uid/gid
	currentUid := syscall.Geteuid()
	currentGid := syscall.Getegid()
	var uid, gid int

	// Lookup user
	if userStr == "-" {
		uid = currentUid
	} else {
		u, err := user.Lookup(userStr)
		if err != nil {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("user lookup failed: %v", err))))
			return nil
		}
		uidInt, err := strconv.Atoi(u.Uid)
		if err != nil {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("invalid user id: %v", err))))
			return nil
		}
		uid = uidInt
	}

	// Lookup group
	if groupStr == "-" {
		gid = currentGid
	} else {
		g, err := user.LookupGroup(groupStr)
		if err != nil {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("group lookup failed: %v", err))))
			return nil
		}
		gidInt, err := strconv.Atoi(g.Gid)
		if err != nil {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("invalid group id: %v", err))))
			return nil
		}
		gid = gidInt
	}

	// Check if we need to change uid/gid
	needUID := uid != currentUid
	needGID := gid != currentGid
	if (needUID || needGID) && !hasRequiredCapabilities(needUID, needGID) {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "insufficient privileges to set UID/GID (not root and missing required capabilities)")))
		return nil
	}

	// Check command against whitelist (use the actual command string)
	allowed := s.config.ShellConfig.AllowedCommands
	if len(allowed) > 0 {
		// Extract base command (first word)
		parts := strings.Fields(commandStr)
		if len(parts) == 0 {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "empty command")))
			return nil
		}
		baseCmd := parts[0]
		found := false
		for _, pattern := range allowed {
			if matchesCommand(pattern, baseCmd) {
				found = true
				break
			}
		}
		if !found {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("command not allowed: %s", baseCmd))))
			return nil
		}
	}

	// Build environment variables
	env := os.Environ()
	for _, envVar := range sess.envVars {
		env = append(env, envVar)
	}

	// Execute command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.ShellConfig.MaxExecutionTime)*time.Second)
	defer cancel()

	fmt.Printf("Executing command as uid=%d gid=%d: %s\n", uid, gid, commandStr)
	execCmd := exec.CommandContext(ctx, "sh", "-c", commandStr)
	execCmd.Env = env
	workingDir, err := s.getAbsWorkingDir(sess)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("invalid working directory: %v", err))))
		return nil
	}
	execCmd.Dir = workingDir

	// Set credentials if needed
	if needUID || needGID {
		execCmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
		}
	}

	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stdout pipe: %v", err))))
		return nil // Don't return error to keep stream open
	}
	stderr, err := execCmd.StderrPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stderr pipe: %v", err))))
		return nil // Don't return error to keep stream open
	}

	if err := execCmd.Start(); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to start command: %v", err))))
		return nil // Don't return error to keep stream open
	}

	// Read stdout and stderr concurrently
	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(&stdoutBuf, stdout)
	}()
	go func() {
		defer wg.Done()
		io.Copy(&stderrBuf, stderr)
	}()
	wg.Wait()

	err = execCmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Send response according to protocol: OK\n<exit_code>\n<stdout_size>\n<stdout>\n<stderr_size>\n<stderr>
	response := fmt.Sprintf("%s\n%d\n%d\n%s\n%d\n%s", protocol.ResponseOK, exitCode, stdoutBuf.Len(), stdoutBuf.String(), stderrBuf.Len(), stderrBuf.String())
	fmt.Printf("Sending command response, exit code: %d, stdout: %d bytes, stderr: %d bytes\n", exitCode, stdoutBuf.Len(), stderrBuf.Len())
	_, err = stream.Write([]byte(response))
	if err != nil {
		fmt.Printf("Failed to send response: %v\n", err)
		return nil // Don't return error to keep stream open
	}

	// Clear environment variables after command execution
	sess.envVars = nil
	return nil
}

func (s *Server) handleEnv(stream *quic.Stream, cmd *protocol.Command, sess *session) error {
	envVar := cmd.Args[0]
	fmt.Printf("Setting environment variable: %s\n", envVar)
	parts := strings.SplitN(envVar, "=", 2)
	if len(parts) != 2 {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "invalid format, use NAME=VALUE")))
		return nil
	}
	name := parts[0]

	// Check if variable is allowed
	allowed := s.config.ShellConfig.AllowedEnvVars
	if len(allowed) > 0 {
		found := false
		for _, v := range allowed {
			if v == name {
				found = true
				break
			}
		}
		if !found {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("environment variable not allowed: %s", name))))
			return nil
		}
	}

	sess.envVars = append(sess.envVars, envVar)
	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, "environment variable set")))
	return nil
}

func (s *Server) handleCD(stream *quic.Stream, cmd *protocol.Command, sess *session) error {
	if len(cmd.Args) == 0 {
		sess.workingDir = "."
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, "changed directory to home")))
		return nil
	}
	newDir := cmd.Args[0]
	var targetPath string
	if filepath.IsAbs(newDir) {
		targetPath = newDir
	} else {
		targetPath = filepath.Join(sess.workingDir, newDir)
	}
	absPath, err := s.resolvePathRelativeToHome(targetPath, sess.homeDir)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("invalid directory: %v", err))))
		return nil
	}
	info, err := os.Stat(absPath)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("directory not accessible: %v", err))))
		return nil
	}
	if !info.IsDir() {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "not a directory")))
		return nil
	}
	relPath, err := filepath.Rel(sess.homeDir, absPath)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "cannot compute relative path")))
		return nil
	}
	sess.workingDir = relPath
	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("changed directory to %s", relPath))))
	return nil
}
