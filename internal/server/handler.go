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
	"github.com/francesco/quics/internal/webhook"
	"github.com/quic-go/quic-go"
)

type Server struct {
	config   *Config
	notifier webhook.Notifier
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
	userid  string
	envVars []string
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
				hasSetuid := (capEff & (1 << 7)) != 0
				hasSetgid := (capEff & (1 << 6)) != 0
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

func NewServer(config *Config, notifier webhook.Notifier) *Server {
	return &Server{config: config, notifier: notifier}
}

// notify sends a webhook notification asynchronously
func (s *Server) notify(action string, sess *session, success bool, errMsg string, details map[string]interface{}) {
	if s.notifier == nil {
		return
	}
	s.notifier.Notify(action, sess.userid, success, errMsg, details)
}

func (s *Server) HandleStream(stream *quic.Stream, userid string) error {
	defer stream.Close()

	sess := &session{userid: userid}
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
		default:
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "unknown command")))
			return fmt.Errorf("unknown command type: %s", cmd.Type)
		}
	}
}

func (s *Server) handleUpload(stream *quic.Stream, cmd *protocol.Command, sess *session, reader *bufio.Reader) error {
	filename := cmd.Args[0]
	filePath := filepath.Join(s.config.StorageRoot, filename)

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create directory: %v", err))))
		s.notify("upload", sess, false, err.Error(), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create file: %v", err))))
		s.notify("upload", sess, false, err.Error(), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
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
		s.notify("upload", sess, false, err.Error(), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		return err
	}

	if written != cmd.Size {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("incomplete transfer: expected %d bytes, got %d", cmd.Size, written))))
		s.notify("upload", sess, false, fmt.Sprintf("incomplete transfer: expected %d bytes, got %d", cmd.Size, written), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
			"written":  written,
		})
		return fmt.Errorf("incomplete transfer")
	}

	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("%d bytes written", written))))
	s.notify("upload", sess, true, "", map[string]interface{}{
		"filename": filename,
		"size":     cmd.Size,
		"mode":     cmd.Mode,
		"written":  written,
	})
	return nil
}

func (s *Server) handleDownload(stream *quic.Stream, cmd *protocol.Command, sess *session) error {
	filename := cmd.Args[0]
	filePath := filepath.Join(s.config.StorageRoot, filename)
	fmt.Printf("Download request for: %s (path: %s)\n", filename, filePath)

	file, err := os.Open(filePath)
	if err != nil {
		var errMsg string
		if os.IsNotExist(err) {
			errMsg = "file not found"
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		} else {
			errMsg = fmt.Sprintf("failed to open file: %v", err)
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		}
		s.notify("download", sess, false, errMsg, map[string]interface{}{
			"filename": filename,
			"mode":     cmd.Mode,
		})
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to stat file: %v", err))))
		s.notify("download", sess, false, fmt.Sprintf("failed to stat file: %v", err), map[string]interface{}{
			"filename": filename,
			"mode":     cmd.Mode,
		})
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
		s.notify("download", sess, false, fmt.Sprintf("failed to send file: %v", err), map[string]interface{}{
			"filename": filename,
			"mode":     cmd.Mode,
			"size":     size,
		})
		return fmt.Errorf("failed to send file: %w", err)
	}
	fmt.Printf("File sent successfully, size: %d, sent: %d\n", size, n)
	s.notify("download", sess, true, "", map[string]interface{}{
		"filename": filename,
		"mode":     cmd.Mode,
		"size":     size,
		"sent":     n,
	})
	return nil
}

func (s *Server) handleCommand(stream *quic.Stream, cmd *protocol.Command, sess *session) error {
	if !s.config.ShellConfig.Enabled {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "shell execution is disabled")))
		s.notify("command", sess, false, "shell execution is disabled", map[string]interface{}{
			"command": strings.Join(cmd.Args, " "),
		})
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

	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stdout pipe: %v", err))))
		s.notify("command", sess, false, fmt.Sprintf("failed to create stdout pipe: %v", err), map[string]interface{}{
			"command": cmdStr,
		})
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
		s.notify("exec", sess, false, "shell execution is disabled", map[string]interface{}{
			"command": strings.Join(cmd.Args, " "),
		})
		return nil
	}

	// Parse arguments: user, group, command
	if len(cmd.Args) < 3 {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "EXEC requires user, group and command")))
		s.notify("exec", sess, false, "EXEC requires user, group and command", map[string]interface{}{
			"command": strings.Join(cmd.Args, " "),
		})
		return nil
	}
	userStr := cmd.Args[0]
	groupStr := cmd.Args[1]
	commandStr := cmd.Args[2]

	// Check if we're on Linux
	if runtime.GOOS != "linux" {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "EXEC is only supported on Linux")))
		s.notify("exec", sess, false, "EXEC is only supported on Linux", map[string]interface{}{
			"command": commandStr,
			"user":    userStr,
			"group":   groupStr,
		})
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
		errMsg := "invalid format, use NAME=VALUE"
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		s.notify("env", sess, false, errMsg, map[string]interface{}{
			"envVar": envVar,
		})
		return nil
	}
	name := parts[0]
	value := parts[1]

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
			errMsg := fmt.Sprintf("environment variable not allowed: %s", name)
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
			s.notify("env", sess, false, errMsg, map[string]interface{}{
				"name":  name,
				"value": value,
			})
			return nil
		}
	}

	sess.envVars = append(sess.envVars, envVar)
	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, "environment variable set")))
	s.notify("env", sess, true, "", map[string]interface{}{
		"name":  name,
		"value": value,
	})
	return nil
}
